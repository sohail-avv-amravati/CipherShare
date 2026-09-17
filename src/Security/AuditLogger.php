<?php
namespace Security;

use Database\Database;

class AuditLogger {
    /**
     * Comprehensive logger for CipherShare audit records.
     */
    public static function logEvent(
        ?int $actorUserId = null,
        ?string $actorUsername = null,
        string $actorRole = 'USER',
        string $eventCategory = 'GENERAL',
        string $eventType = 'EVENT',
        ?int $targetUserId = null,
        ?int $targetFileId = null,
        ?int $targetShareId = null,
        ?string $description = null
    ): void {
        try {
            $db = Database::getInstance();
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

            // Sanitize description to ensure no sensitive tokens/hashes/passwords are ever logged
            if ($description !== null) {
                $description = preg_replace('/(password|token|hash|key|answer)\s*[:=]\s*\S+/i', '$1:[REDACTED]', $description);
            }

            $stmt = $db->prepare("
                INSERT INTO audit_logs 
                (actor_user_id, actor_username, actor_role, event_category, event_type, target_user_id, target_file_id, target_share_id, description, ip_address, created_at)
                VALUES 
                (:actor_id, :actor_user, :actor_role, :category, :event_type, :target_user, :target_file, :target_share, :description, :ip, CURRENT_TIMESTAMP)
            ");
            $stmt->execute([
                ':actor_id' => $actorUserId,
                ':actor_user' => $actorUsername,
                ':actor_role' => $actorRole,
                ':category' => strtoupper($eventCategory),
                ':event_type' => strtoupper($eventType),
                ':target_user' => $targetUserId,
                ':target_file' => $targetFileId,
                ':target_share' => $targetShareId,
                ':description' => $description,
                ':ip' => $ip
            ]);
        } catch (\Exception $e) {
            // Silently catch to preserve main application flow
        }
    }

    /**
     * Backwards-compatible log method.
     */
    public static function log(?int $userId, string $action, ?string $details = null): void {
        $actorUsername = null;
        $role = 'USER';
        if ($userId) {
            try {
                $db = Database::getInstance();
                $stmt = $db->prepare("SELECT username, role FROM users WHERE id = :id");
                $stmt->execute([':id' => $userId]);
                $u = $stmt->fetch();
                if ($u) {
                    $actorUsername = $u['username'];
                    $role = $u['role'];
                }
            } catch (\Exception $e) {}
        }
        self::logEvent(
            $userId,
            $actorUsername,
            $role,
            'GENERAL',
            strtoupper($action),
            null,
            null,
            null,
            $details
        );
    }

    /**
     * Record security events for explicit security monitoring.
     */
    public static function logSecurityEvent(?int $userId, string $eventType, ?string $details = null): void {
        try {
            $db = Database::getInstance();
            $stmt = $db->prepare("INSERT INTO security_events (user_id, event_type, details, created_at) VALUES (:user_id, :event_type, :details, CURRENT_TIMESTAMP)");
            $stmt->execute([
                ':user_id' => $userId,
                ':event_type' => strtoupper($eventType),
                ':details' => $details
            ]);

            // Also mirror as a SECURITY category audit log entry
            $actorUsername = null;
            $role = 'USER';
            if ($userId) {
                $stmtU = $db->prepare("SELECT username, role FROM users WHERE id = :id");
                $stmtU->execute([':id' => $userId]);
                if ($u = $stmtU->fetch()) {
                    $actorUsername = $u['username'];
                    $role = $u['role'];
                }
            }

            self::logEvent(
                $userId,
                $actorUsername,
                $role,
                'SECURITY',
                strtoupper($eventType),
                null,
                null,
                null,
                $details
            );
        } catch (\Exception $e) {
            // Fail silently
        }
    }
}
