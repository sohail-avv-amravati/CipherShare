<?php
namespace Files;

use Database\Database;
use Security\AuditLogger;
use Crypto\AES256GCM;
use PDO;

class FileManager {

    private static array $allowedExtensions = [
        'txt', 'pdf', 'jpg', 'jpeg', 'png', 'gif', 'docx', 'xlsx', 'pptx', 'zip', 'mp3', 'mp4', 'csv', 'json'
    ];

    /**
     * Upload file safely (Atomic: validate -> move -> DB insert -> log)
     */
    public static function uploadFile(int $userId, array $fileArray, ?string &$error = null): ?array {
        // 1. Parameter structure check
        if (!isset($fileArray['error']) || is_array($fileArray['error'])) {
            $error = "Please select a file.";
            return null;
        }

        // 2. Upload Error Code Handling
        switch ($fileArray['error']) {
            case UPLOAD_ERR_OK:
                break;
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $error = "The selected file is too large.";
                return null;
            case UPLOAD_ERR_PARTIAL:
                $error = "File upload was interrupted. Please try again.";
                return null;
            case UPLOAD_ERR_NO_FILE:
                $error = "Please select a file.";
                return null;
            case UPLOAD_ERR_NO_TMP_DIR:
            case UPLOAD_ERR_CANT_WRITE:
                $error = "File upload failed due to a server storage issue.";
                return null;
            default:
                $error = "File upload failed. Please try again.";
                return null;
        }

        // 3. Check file size
        $fileSize = (int)($fileArray['size'] ?? 0);
        if ($fileSize <= 0) {
            $error = "Empty files are not supported.";
            return null;
        }

        if ($fileSize > 50 * 1024 * 1024) { // 50 MB limit
            $error = "The selected file is too large.";
            return null;
        }

        // 4. Safe filename handling & path traversal protection
        $rawName = (string)($fileArray['name'] ?? 'file');
        // Extract base filename first to strip out directory paths
        $baseName = basename(str_replace('\\', '/', $rawName));
        // Remove leading dots or path traversal artifacts
        $baseName = ltrim($baseName, '.');
        $originalName = sanitize($baseName);

        if (empty($originalName)) {
            $originalName = "unnamed_file";
        }

        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (empty($ext) || !in_array($ext, self::$allowedExtensions)) {
            $error = "That file type is not supported.";
            return null;
        }

        // 5. Server-side MIME type detection
        $mimeType = 'application/octet-stream';
        if (!empty($fileArray['tmp_name']) && file_exists($fileArray['tmp_name'])) {
            if (function_exists('finfo_open')) {
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime = @finfo_file($finfo, $fileArray['tmp_name']);
                if ($finfo) finfo_close($finfo);
                if ($mime) {
                    $mimeType = $mime;
                }
            } elseif (function_exists('mime_content_type')) {
                $mime = @mime_content_type($fileArray['tmp_name']);
                if ($mime) {
                    $mimeType = $mime;
                }
            }
        }

        // 6. Generate unique internal stored filename
        $storedName = bin2hex(random_bytes(16)) . '.' . $ext;
        $targetPath = STORAGE_UPLOADS . '/' . $storedName;

        // Ensure storage directory exists
        if (!is_dir(STORAGE_UPLOADS)) {
            @mkdir(STORAGE_UPLOADS, 0755, true);
        }

        // 7. Move file to target storage directory
        $tmpPath = $fileArray['tmp_name'] ?? '';
        if (empty($tmpPath) || !file_exists($tmpPath)) {
            $error = "File upload failed. Please try again.";
            return null;
        }

        $moved = false;
        if (is_uploaded_file($tmpPath)) {
            $moved = move_uploaded_file($tmpPath, $targetPath);
        } else {
            // For programmatic execution / unit tests
            $moved = @copy($tmpPath, $targetPath);
        }

        if (!$moved || !file_exists($targetPath)) {
            $error = "File upload failed. Please try again.";
            return null;
        }

        // 8. Atomic Database Record Creation
        $db = Database::getInstance();
        try {
            $stmtU = $db->prepare("SELECT username, role FROM users WHERE id = :id");
            $stmtU->execute([':id' => $userId]);
            $u = $stmtU->fetch();
            $username = $u['username'] ?? "user_{$userId}";
            $role = $u['role'] ?? 'USER';

            $stmt = $db->prepare("
                INSERT INTO files (user_id, original_name, stored_name, mime_type, file_size, is_encrypted, cipher_alg, created_at)
                VALUES (:user_id, :original_name, :stored_name, :mime_type, :file_size, 0, NULL, CURRENT_TIMESTAMP)
            ");
            $stmt->execute([
                ':user_id' => $userId,
                ':original_name' => $originalName,
                ':stored_name' => $storedName,
                ':mime_type' => $mimeType,
                ':file_size' => $fileSize
            ]);

            $fileId = (int)$db->lastInsertId();

            AuditLogger::logEvent(
                $userId,
                $username,
                $role,
                'FILE',
                'FILE_UPLOADED',
                $userId,
                $fileId,
                null,
                "Uploaded file '{$originalName}' (" . format_file_size($fileSize) . ")"
            );

            return [
                'id' => $fileId,
                'original_name' => $originalName,
                'stored_name' => $storedName,
                'size' => $fileSize,
                'mime_type' => $mimeType
            ];
        } catch (\Exception $e) {
            // Cleanup orphaned file on disk if DB insertion fails
            if (file_exists($targetPath)) {
                @unlink($targetPath);
            }
            $error = "File upload failed. Please try again.";
            return null;
        }
    }

    /**
     * Get user's file record by ID with authorization check
     */
    public static function getUserFile(int $userId, int $fileId): ?array {
        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT * FROM files WHERE id = :id AND user_id = :user_id");
        $stmt->execute([':id' => $fileId, ':user_id' => $userId]);
        $file = $stmt->fetch();
        if (!$file) {
            $stmtExists = $db->prepare("SELECT user_id, original_name FROM files WHERE id = :id");
            $stmtExists->execute([':id' => $fileId]);
            $other = $stmtExists->fetch();
            if ($other && $other['user_id'] != $userId) {
                AuditLogger::logEvent(
                    $userId,
                    null,
                    'USER',
                    'SECURITY',
                    'INVALID_FILE_ACCESS',
                    (int)$other['user_id'],
                    $fileId,
                    null,
                    "Unauthorized attempt to access private file ID {$fileId}"
                );
            }
        }
        return $file ?: null;
    }

    /**
     * Get user's file list
     */
    public static function getUserFiles(int $userId): array {
        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT * FROM files WHERE user_id = :user_id ORDER BY created_at DESC");
        $stmt->execute([':user_id' => $userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Encrypt an existing file with AES-256-GCM
     */
    public static function encryptUserFile(int $userId, int $fileId, string $passphrase, ?string &$error = null): bool {
        $file = self::getUserFile($userId, $fileId);
        if (!$file) {
            $error = "File not found or access denied.";
            return false;
        }

        $sourcePath = ($file['is_encrypted'] ? STORAGE_ENCRYPTED : STORAGE_UPLOADS) . '/' . $file['stored_name'];
        if (!file_exists($sourcePath)) {
            $error = "File content missing on storage system.";
            return false;
        }

        $rawContent = file_get_contents($sourcePath);
        if ($rawContent === false) {
            $error = "Unable to read file content.";
            return false;
        }

        try {
            $encryptedStream = AES256GCM::encryptFileContent($rawContent, $passphrase, $file['original_name'], $file['mime_type']);
            
            $newStoredName = bin2hex(random_bytes(16)) . '.enc';
            $targetPath = STORAGE_ENCRYPTED . '/' . $newStoredName;

            if (file_put_contents($targetPath, $encryptedStream) === false) {
                $error = "Failed to write encrypted container to storage.";
                return false;
            }

            if (file_exists($sourcePath) && !$file['is_encrypted']) {
                unlink($sourcePath);
            }

            $db = Database::getInstance();
            $stmt = $db->prepare("
                UPDATE files 
                SET stored_name = :stored_name, 
                    is_encrypted = 1, 
                    cipher_alg = 'AES-256-GCM', 
                    file_size = :file_size 
                WHERE id = :id
            ");
            $stmt->execute([
                ':stored_name' => $newStoredName,
                ':file_size' => strlen($encryptedStream),
                ':id' => $fileId
            ]);

            $stmtU = $db->prepare("SELECT username, role FROM users WHERE id = :id");
            $stmtU->execute([':id' => $userId]);
            $u = $stmtU->fetch();

            AuditLogger::logEvent(
                $userId,
                $u['username'] ?? null,
                $u['role'] ?? 'USER',
                'FILE',
                'FILE_ENCRYPTED',
                $userId,
                $fileId,
                null,
                "Encrypted file '{$file['original_name']}' with AES-256-GCM"
            );
            return true;
        } catch (\Exception $e) {
            $error = $e->getMessage();
            return false;
        }
    }

    /**
     * Decrypt file content with passphrase
     */
    public static function decryptUserFile(int $userId, int $fileId, string $passphrase, ?string &$error = null): ?array {
        $file = self::getUserFile($userId, $fileId);
        if (!$file) {
            $error = "File not found or access denied.";
            return null;
        }

        if (!$file['is_encrypted']) {
            $error = "File is not encrypted.";
            return null;
        }

        $encPath = STORAGE_ENCRYPTED . '/' . $file['stored_name'];
        if (!file_exists($encPath)) {
            $error = "Encrypted file missing from storage.";
            return null;
        }

        $container = file_get_contents($encPath);
        try {
            $decrypted = AES256GCM::decryptFileContent($container, $passphrase);

            $db = Database::getInstance();
            $stmtU = $db->prepare("SELECT username, role FROM users WHERE id = :id");
            $stmtU->execute([':id' => $userId]);
            $u = $stmtU->fetch();

            AuditLogger::logEvent(
                $userId,
                $u['username'] ?? null,
                $u['role'] ?? 'USER',
                'FILE',
                'FILE_DECRYPTED',
                $userId,
                $fileId,
                null,
                "Successfully decrypted file '{$file['original_name']}'"
            );

            return $decrypted;
        } catch (\Exception $e) {
            AuditLogger::logSecurityEvent($userId, "DECRYPT_FAILED", "Failed decryption attempt on file ID {$fileId} ('{$file['original_name']}')");
            $error = "Decryption failed. Please check your passphrase.";
            return null;
        }
    }

    /**
     * Delete file
     */
    public static function deleteUserFile(int $userId, int $fileId, ?string &$error = null): bool {
        $file = self::getUserFile($userId, $fileId);
        if (!$file) {
            $error = "File not found or access denied.";
            return false;
        }

        $filePath = ($file['is_encrypted'] ? STORAGE_ENCRYPTED : STORAGE_UPLOADS) . '/' . $file['stored_name'];
        if (file_exists($filePath)) {
            unlink($filePath);
        }

        $db = Database::getInstance();
        $stmtU = $db->prepare("SELECT username, role FROM users WHERE id = :id");
        $stmtU->execute([':id' => $userId]);
        $u = $stmtU->fetch();

        $stmt = $db->prepare("DELETE FROM files WHERE id = :id");
        $stmt->execute([':id' => $fileId]);

        AuditLogger::logEvent(
            $userId,
            $u['username'] ?? null,
            $u['role'] ?? 'USER',
            'FILE',
            'FILE_DELETED',
            $userId,
            $fileId,
            null,
            "Deleted file '{$file['original_name']}'"
        );
        return true;
    }
}
