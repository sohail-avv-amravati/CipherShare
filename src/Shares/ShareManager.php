<?php
namespace Shares;

use Database\Database;
use Files\FileManager;
use Security\AuditLogger;
use PDO;

class ShareManager {

    public static array $expirationOptions = [
        '30m'  => ['label' => '30 Minutes', 'seconds' => 1800],
        '1h'   => ['label' => '1 Hour',     'seconds' => 3600],
        '6h'   => ['label' => '6 Hours',    'seconds' => 21600],
        '12h'  => ['label' => '12 Hours',   'seconds' => 43200],
        '1d'   => ['label' => '1 Day',      'seconds' => 86400],
    ];

    /**
     * Create a file share with a recipient username
     */
    public static function createShare(int $senderId, int $fileId, string $recipientUsername, string $durationKey, ?string &$error = null): ?string {
        $recipientUsername = trim($recipientUsername);

        if (empty($recipientUsername)) {
            $error = "Please enter a recipient username.";
            return null;
        }

        if (!isset(self::$expirationOptions[$durationKey])) {
            $error = "Invalid expiration period selected.";
            return null;
        }

        // Verify file ownership
        $file = FileManager::getUserFile($senderId, $fileId);
        if (!$file) {
            $error = "File not found or access denied.";
            return null;
        }

        $db = Database::getInstance();

        // Resolve recipient username
        $stmtRecipient = $db->prepare("SELECT id, username, status FROM users WHERE LOWER(username) = LOWER(:username)");
        $stmtRecipient->execute([':username' => $recipientUsername]);
        $recipient = $stmtRecipient->fetch();

        if (!$recipient) {
            $error = "Recipient username '{$recipientUsername}' does not exist.";
            return null;
        }

        if ($recipient['status'] !== 'ACTIVE') {
            $error = "Recipient user account is not active.";
            return null;
        }

        if ((int)$recipient['id'] === $senderId) {
            $error = "You cannot share a file with yourself.";
            return null;
        }

        $shareId = bin2hex(random_bytes(16));
        $seconds = self::$expirationOptions[$durationKey]['seconds'];
        $expiresAt = date('Y-m-d H:i:s', time() + $seconds);

        $stmtInsert = $db->prepare("
            INSERT INTO shares (share_id, sender_id, recipient_id, file_id, status, created_at, expires_at)
            VALUES (:share_id, :sender_id, :recipient_id, :file_id, 'PENDING', CURRENT_TIMESTAMP, :expires_at)
        ");
        $stmtInsert->execute([
            ':share_id' => $shareId,
            ':sender_id' => $senderId,
            ':recipient_id' => $recipient['id'],
            ':file_id' => $fileId,
            ':expires_at' => $expiresAt
        ]);

        $dbShareId = (int)$db->lastInsertId();

        $stmtSender = $db->prepare("SELECT username, role FROM users WHERE id = :id");
        $stmtSender->execute([':id' => $senderId]);
        $sender = $stmtSender->fetch();

        AuditLogger::logEvent(
            $senderId,
            $sender['username'] ?? null,
            $sender['role'] ?? 'USER',
            'SHARE',
            'SHARE_CREATED',
            (int)$recipient['id'],
            $fileId,
            $dbShareId,
            "Shared file '{$file['original_name']}' with {$recipient['username']} (Expires: " . date('d M Y, h:i A', strtotime($expiresAt)) . ")"
        );

        return $shareId;
    }

    /**
     * Check and update lazy share expiration based on server time
     */
    private static function checkShareStatus(array &$share): void {
        if ($share['status'] === 'PENDING') {
            $now = time();
            $expiresTime = strtotime($share['expires_at']);
            if ($now >= $expiresTime) {
                $share['status'] = 'FAILED';
                $share['failure_reason'] = "Recipient did not access the file before the expiration time.";

                $db = Database::getInstance();
                $stmt = $db->prepare("UPDATE shares SET status = 'FAILED', failure_reason = :reason WHERE id = :id AND status = 'PENDING'");
                $stmt->execute([
                    ':reason' => $share['failure_reason'],
                    ':id' => $share['id']
                ]);

                AuditLogger::logEvent(
                    (int)$share['sender_id'],
                    null,
                    'USER',
                    'SHARE',
                    'SHARE_EXPIRED',
                    (int)$share['recipient_id'],
                    (int)$share['file_id'],
                    (int)$share['id'],
                    "Share for file expired because recipient did not access it before expiration time"
                );
            }
        }
    }

    /**
     * Get sent shares for a user
     */
    public static function getSentShares(int $senderId): array {
        $db = Database::getInstance();
        $stmt = $db->prepare("
            SELECT s.*, f.original_name, f.is_encrypted, u.username AS recipient_username
            FROM shares s
            JOIN files f ON s.file_id = f.id
            JOIN users u ON s.recipient_id = u.id
            WHERE s.sender_id = :sender_id
            ORDER BY s.created_at DESC
        ");
        $stmt->execute([':sender_id' => $senderId]);
        $shares = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($shares as &$share) {
            self::checkShareStatus($share);
        }
        return $shares;
    }

    /**
     * Get received shares for a user
     */
    public static function getReceivedShares(int $recipientId): array {
        $db = Database::getInstance();
        $stmt = $db->prepare("
            SELECT s.*, f.original_name, f.mime_type, f.file_size, f.is_encrypted, u.username AS sender_username
            FROM shares s
            JOIN files f ON s.file_id = f.id
            JOIN users u ON s.sender_id = u.id
            WHERE s.recipient_id = :recipient_id
            ORDER BY s.created_at DESC
        ");
        $stmt->execute([':recipient_id' => $recipientId]);
        $shares = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($shares as &$share) {
            self::checkShareStatus($share);
        }
        return $shares;
    }

    /**
     * Access and download a shared file
     */
    public static function accessSharedFile(int $recipientId, string $shareId, ?string &$error = null): ?array {
        $db = Database::getInstance();
        $stmt = $db->prepare("
            SELECT s.*, f.original_name, f.stored_name, f.mime_type, f.file_size, f.is_encrypted
            FROM shares s
            JOIN files f ON s.file_id = f.id
            WHERE s.share_id = :share_id AND s.recipient_id = :recipient_id
        ");
        $stmt->execute([':share_id' => $shareId, ':recipient_id' => $recipientId]);
        $share = $stmt->fetch();

        if (!$share) {
            $error = "Share not found or access denied.";
            return null;
        }

        self::checkShareStatus($share);

        if ($share['status'] === 'FAILED' || $share['status'] === 'EXPIRED') {
            $error = $share['failure_reason'] ?? "Recipient did not access the file before the expiration time.";
            AuditLogger::logEvent(
                $recipientId,
                null,
                'USER',
                'SHARE',
                'SHARE_FAILED',
                (int)$share['sender_id'],
                (int)$share['file_id'],
                (int)$share['id'],
                "Attempted to access expired share"
            );
            return null;
        }

        if ($share['status'] === 'CANCELLED') {
            $error = "This share was cancelled by the sender.";
            return null;
        }

        if ($share['status'] === 'PENDING') {
            $stmtSuccess = $db->prepare("UPDATE shares SET status = 'SUCCESS', accessed_at = CURRENT_TIMESTAMP WHERE id = :id");
            $stmtSuccess->execute([':id' => $share['id']]);
            $share['status'] = 'SUCCESS';
            $share['accessed_at'] = date('Y-m-d H:i:s');

            $stmtRec = $db->prepare("SELECT username, role FROM users WHERE id = :id");
            $stmtRec->execute([':id' => $recipientId]);
            $rec = $stmtRec->fetch();

            AuditLogger::logEvent(
                $recipientId,
                $rec['username'] ?? null,
                $rec['role'] ?? 'USER',
                'SHARE',
                'SHARE_ACCESSED',
                (int)$share['sender_id'],
                (int)$share['file_id'],
                (int)$share['id'],
                "Recipient accessed shared file '{$share['original_name']}' before expiration"
            );

            AuditLogger::logEvent(
                $recipientId,
                $rec['username'] ?? null,
                $rec['role'] ?? 'USER',
                'SHARE',
                'SHARE_COMPLETED',
                (int)$share['sender_id'],
                (int)$share['file_id'],
                (int)$share['id'],
                "Share transfer completed successfully"
            );
        }

        $filePath = ($share['is_encrypted'] ? STORAGE_ENCRYPTED : STORAGE_UPLOADS) . '/' . $share['stored_name'];

        if (!file_exists($filePath)) {
            $error = "Target file is missing on server storage.";
            return null;
        }

        return [
            'share' => $share,
            'file_path' => $filePath,
            'original_name' => $share['original_name'],
            'mime_type' => $share['mime_type'],
            'is_encrypted' => $share['is_encrypted']
        ];
    }

    /**
     * Cancel a pending share (by sender)
     */
    public static function cancelShare(int $senderId, string $shareId, ?string &$error = null): bool {
        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT * FROM shares WHERE share_id = :share_id AND sender_id = :sender_id");
        $stmt->execute([':share_id' => $shareId, ':sender_id' => $senderId]);
        $share = $stmt->fetch();

        if (!$share) {
            $error = "Share not found or access denied.";
            return false;
        }

        if ($share['status'] !== 'PENDING') {
            $error = "Only pending shares can be cancelled.";
            return false;
        }

        $stmtCancel = $db->prepare("UPDATE shares SET status = 'CANCELLED' WHERE id = :id");
        $stmtCancel->execute([':id' => $share['id']]);

        $stmtSend = $db->prepare("SELECT username, role FROM users WHERE id = :id");
        $stmtSend->execute([':id' => $senderId]);
        $sender = $stmtSend->fetch();

        AuditLogger::logEvent(
            $senderId,
            $sender['username'] ?? null,
            $sender['role'] ?? 'USER',
            'SHARE',
            'SHARE_CANCELLED',
            (int)$share['recipient_id'],
            (int)$share['file_id'],
            (int)$share['id'],
            "Sender cancelled pending share"
        );

        return true;
    }
}
