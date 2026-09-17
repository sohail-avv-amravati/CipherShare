<?php
namespace Owner;

use Database\Database;
use Security\AuditLogger;
use PDO;

class OwnerManager {

    /**
     * Get aggregated Dashboard statistics for Owner
     */
    public static function getDashboardStats(): array {
        $db = Database::getInstance();

        // User stats
        $usersTotal = (int)$db->query("SELECT COUNT(*) FROM users WHERE role = 'USER'")->fetchColumn();
        $usersActive = (int)$db->query("SELECT COUNT(*) FROM users WHERE role = 'USER' AND status = 'ACTIVE'")->fetchColumn();
        $usersSuspended = (int)$db->query("SELECT COUNT(*) FROM users WHERE role = 'USER' AND status = 'SUSPENDED'")->fetchColumn();
        $usersDeactivated = (int)$db->query("SELECT COUNT(*) FROM users WHERE role = 'USER' AND status = 'DEACTIVATED'")->fetchColumn();

        // File stats
        $filesTotal = (int)$db->query("SELECT COUNT(*) FROM files")->fetchColumn();
        $filesEncrypted = (int)$db->query("SELECT COUNT(*) FROM files WHERE is_encrypted = 1")->fetchColumn();
        $storageBytes = (int)$db->query("SELECT SUM(file_size) FROM files")->fetchColumn() ?: 0;

        // Share stats
        $sharesTotal = (int)$db->query("SELECT COUNT(*) FROM shares")->fetchColumn();
        $sharesPending = (int)$db->query("SELECT COUNT(*) FROM shares WHERE status = 'PENDING'")->fetchColumn();
        $sharesSuccess = (int)$db->query("SELECT COUNT(*) FROM shares WHERE status = 'SUCCESS'")->fetchColumn();
        $sharesFailed = (int)$db->query("SELECT COUNT(*) FROM shares WHERE status IN ('FAILED', 'EXPIRED')")->fetchColumn();
        $sharesCancelled = (int)$db->query("SELECT COUNT(*) FROM shares WHERE status = 'CANCELLED'")->fetchColumn();
        
        $successRate = ($sharesTotal > 0) ? round(($sharesSuccess / $sharesTotal) * 100, 1) : 0;

        // Security stats
        $failedLogins = (int)$db->query("SELECT COUNT(*) FROM login_attempts WHERE success = 0")->fetchColumn();
        $failedResets = (int)$db->query("SELECT COUNT(*) FROM security_events WHERE event_type IN ('RESET_VERIFY_FAILED', 'PASSWORD_RESET_FAILED')")->fetchColumn();
        $suspiciousEvents = (int)$db->query("SELECT COUNT(*) FROM security_events")->fetchColumn();

        return [
            'users' => [
                'total' => $usersTotal,
                'active' => $usersActive,
                'suspended' => $usersSuspended,
                'deactivated' => $usersDeactivated
            ],
            'files' => [
                'total' => $filesTotal,
                'encrypted' => $filesEncrypted,
                'storage_bytes' => $storageBytes,
                'storage_formatted' => self::formatBytes($storageBytes)
            ],
            'shares' => [
                'total' => $sharesTotal,
                'pending' => $sharesPending,
                'success' => $sharesSuccess,
                'failed' => $sharesFailed,
                'cancelled' => $sharesCancelled,
                'success_rate' => $successRate
            ],
            'security' => [
                'failed_logins' => $failedLogins,
                'failed_resets' => $failedResets,
                'suspicious_events' => $suspiciousEvents
            ]
        ];
    }

    /**
     * Get user list for Owner management with objective security indicators
     */
    public static function getUsers(?string $search = null, ?string $statusFilter = null): array {
        $db = Database::getInstance();
        $sql = "
            SELECT u.id, u.username, u.role, u.status, u.created_at, u.last_login_at,
                   (SELECT COUNT(*) FROM files WHERE user_id = u.id) AS file_count,
                   (SELECT COUNT(*) FROM shares WHERE sender_id = u.id) AS shares_sent_count,
                   (SELECT COUNT(*) FROM login_attempts WHERE LOWER(identifier) = LOWER('login:' || u.username) AND success = 0 AND attempted_at >= datetime('now', '-1 hour')) AS failed_logins_1h,
                   (SELECT COUNT(*) FROM security_events WHERE user_id = u.id AND event_type LIKE '%RESET%') AS failed_resets_count,
                   (SELECT COUNT(*) FROM audit_logs WHERE actor_user_id = u.id AND event_category = 'SECURITY') AS security_events_count
            FROM users u
            WHERE u.role = 'USER'
        ";

        $params = [];
        if ($search) {
            $sql .= " AND LOWER(u.username) LIKE LOWER(:search)";
            $params[':search'] = '%' . trim($search) . '%';
        }

        if ($statusFilter && in_array($statusFilter, ['ACTIVE', 'SUSPENDED', 'DEACTIVATED'])) {
            $sql .= " AND u.status = :status";
            $params[':status'] = $statusFilter;
        }

        $sql .= " ORDER BY u.created_at DESC";

        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Update user status (ACTIVE, SUSPENDED, DEACTIVATED)
     */
    public static function updateUserStatus(int $ownerUserId, int $targetUserId, string $newStatus, ?string &$error = null): bool {
        if (!in_array($newStatus, ['ACTIVE', 'SUSPENDED', 'DEACTIVATED'])) {
            $error = "Invalid user status requested.";
            return false;
        }

        $db = Database::getInstance();
        $stmtTarget = $db->prepare("SELECT id, username, role FROM users WHERE id = :id");
        $stmtTarget->execute([':id' => $targetUserId]);
        $target = $stmtTarget->fetch();

        if (!$target) {
            $error = "User not found.";
            return false;
        }

        if ($target['role'] === 'OWNER') {
            $error = "Cannot change status of an Owner account.";
            return false;
        }

        $stmtOwner = $db->prepare("SELECT username FROM users WHERE id = :id");
        $stmtOwner->execute([':id' => $ownerUserId]);
        $owner = $stmtOwner->fetch();

        $stmtUpdate = $db->prepare("UPDATE users SET status = :status WHERE id = :id");
        $stmtUpdate->execute([':status' => $newStatus, ':id' => $targetUserId]);

        $eventType = 'USER_REACTIVATED';
        if ($newStatus === 'SUSPENDED') {
            $eventType = 'USER_SUSPENDED';
        } elseif ($newStatus === 'DEACTIVATED') {
            $eventType = 'USER_DEACTIVATED';
        }

        AuditLogger::logEvent(
            $ownerUserId,
            $owner['username'] ?? 'CipherShare',
            'OWNER',
            'OWNER',
            $eventType,
            $targetUserId,
            null,
            null,
            "Owner changed user '{$target['username']}' status to {$newStatus}"
        );

        return true;
    }

    /**
     * Fetch security events for Owner review
     */
    public static function getSecurityEvents(int $limit = 100): array {
        $db = Database::getInstance();
        $stmt = $db->prepare("
            SELECT se.*, u.username
            FROM security_events se
            LEFT JOIN users u ON se.user_id = u.id
            ORDER BY se.created_at DESC
            LIMIT :limit
        ");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Fetch audit logs for Owner review (backwards compatible)
     */
    public static function getAuditLogs(int $limit = 100): array {
        $res = self::getAuditLogsFiltered([], 1, $limit);
        return $res['items'];
    }

    /**
     * Fetch audit logs with filtering and server-side pagination
     */
    public static function getAuditLogsFiltered(array $filters = [], int $page = 1, int $perPage = 15): array {
        $db = Database::getInstance();
        $where = [];
        $params = [];

        if (!empty($filters['category']) && $filters['category'] !== 'ALL') {
            $where[] = "event_category = :category";
            $params[':category'] = strtoupper($filters['category']);
        }

        if (!empty($filters['event_type'])) {
            $where[] = "event_type LIKE :event_type";
            $params[':event_type'] = '%' . strtoupper(trim($filters['event_type'])) . '%';
        }

        if (!empty($filters['username'])) {
            $where[] = "(LOWER(actor_username) LIKE LOWER(:username) OR actor_user_id IN (SELECT id FROM users WHERE LOWER(username) LIKE LOWER(:username)))";
            $params[':username'] = '%' . trim($filters['username']) . '%';
        }

        if (!empty($filters['date_from'])) {
            $where[] = "created_at >= :date_from";
            $params[':date_from'] = $filters['date_from'] . ' 00:00:00';
        }

        if (!empty($filters['date_to'])) {
            $where[] = "created_at <= :date_to";
            $params[':date_to'] = $filters['date_to'] . ' 23:59:59';
        }

        $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';

        // Count total matching items
        $countSql = "SELECT COUNT(*) FROM audit_logs {$whereClause}";
        $stmtCount = $db->prepare($countSql);
        $stmtCount->execute($params);
        $totalItems = (int)$stmtCount->fetchColumn();

        $totalPages = max(1, (int)ceil($totalItems / $perPage));
        $currentPage = max(1, min($page, $totalPages));
        $offset = ($currentPage - 1) * $perPage;

        // Fetch paginated rows
        $sql = "
            SELECT al.*, 
                   tu.username AS target_username,
                   tf.original_name AS target_file_name
            FROM audit_logs al
            LEFT JOIN users tu ON al.target_user_id = tu.id
            LEFT JOIN files tf ON al.target_file_id = tf.id
            {$whereClause}
            ORDER BY al.created_at DESC
            LIMIT :limit OFFSET :offset
        ";

        $stmt = $db->prepare($sql);
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return [
            'items' => $items,
            'total_items' => $totalItems,
            'total_pages' => $totalPages,
            'current_page' => $currentPage,
            'per_page' => $perPage
        ];
    }

    private static function formatBytes(int $bytes, int $precision = 2): string {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
}
