<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Shares\ShareManager;
use Crypto\AES256GCM;
use Database\Database;
use Security\CSRF;
use Security\AuditLogger;

$user   = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error  = null;
$downloadReady = false;
$downloadToken = null;
$downloadInfo  = null;

$shareId = isset($_GET['share_id']) ? sanitize($_GET['share_id']) : '';

if (empty($shareId)) {
    redirect('/received-shares.php');
}

// ── CLEANUP: purge expired download tokens ────────────────────────────────────
start_secure_session();
if (isset($_SESSION['decrypt_downloads']) && is_array($_SESSION['decrypt_downloads'])) {
    foreach ($_SESSION['decrypt_downloads'] as $k => $v) {
        if (time() - ($v['created_at'] ?? 0) > 600) {
            if (!empty($v['temp_path']) && file_exists($v['temp_path'])) {
                @unlink($v['temp_path']);
            }
            unset($_SESSION['decrypt_downloads'][$k]);
        }
    }
}

// ── Load the share for this recipient ─────────────────────────────────────────
$receivedShares = ShareManager::getReceivedShares($userId);
$shareData = null;
foreach ($receivedShares as $s) {
    if ($s['share_id'] === $shareId) {
        $shareData = $s;
        break;
    }
}

if (!$shareData) {
    set_flash_message('error', 'Share not found or access denied.');
    redirect('/received-shares.php');
}

// Only allow decrypt if the share is SUCCESS (already accessed) or PENDING
if (!in_array($shareData['status'], ['SUCCESS', 'PENDING'], true)) {
    set_flash_message('error', 'This share is no longer available for decryption.');
    redirect('/received-shares.php');
}

// Only encrypted files need this page
if (!$shareData['is_encrypted']) {
    redirect('/received-shares.php?access=' . urlencode($shareId));
}

// If the share is still PENDING, mark it as accessed/SUCCESS now
if ($shareData['status'] === 'PENDING') {
    $accessError = null;
    ShareManager::accessSharedFile($userId, $shareId, $accessError);
    // Reload share data to reflect updated status
    $receivedShares = ShareManager::getReceivedShares($userId);
    foreach ($receivedShares as $s) {
        if ($s['share_id'] === $shareId) {
            $shareData = $s;
            break;
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// DOWNLOAD HANDLER — GET ?download=TOKEN
// ══════════════════════════════════════════════════════════════════════════════
if (isset($_GET['download']) && !empty($_GET['download'])) {
    $token = $_GET['download'];

    if (!isset($_SESSION['decrypt_downloads'][$token])) {
        $error = "Download link has expired or is invalid. Please decrypt the file again.";
    } else {
        $dl = $_SESSION['decrypt_downloads'][$token];

        if ((int)($dl['user_id'] ?? 0) !== $userId) {
            unset($_SESSION['decrypt_downloads'][$token]);
            $error = "Access denied.";
        } elseif (time() - ($dl['created_at'] ?? 0) > 600) {
            if (!empty($dl['temp_path']) && file_exists($dl['temp_path'])) {
                @unlink($dl['temp_path']);
            }
            unset($_SESSION['decrypt_downloads'][$token]);
            $error = "Download link has expired. Please decrypt the file again.";
        } elseif (empty($dl['temp_path']) || !file_exists($dl['temp_path']) || !is_file($dl['temp_path']) || !is_readable($dl['temp_path'])) {
            unset($_SESSION['decrypt_downloads'][$token]);
            $error = "Decrypted file is no longer available. Please decrypt again.";
        } else {
            // Path security: verify temp file is inside STORAGE_TEMP
            $realPath = realpath($dl['temp_path']);
            $realTemp = realpath(STORAGE_TEMP);
            if ($realPath === false || $realTemp === false || strpos($realPath, $realTemp) !== 0) {
                unset($_SESSION['decrypt_downloads'][$token]);
                $error = "Download failed due to a security check.";
            } else {
                $fileSize = filesize($dl['temp_path']);
                if ($fileSize === false || $fileSize <= 0) {
                    @unlink($dl['temp_path']);
                    unset($_SESSION['decrypt_downloads'][$token]);
                    $error = "Decrypted file appears to be empty or corrupted.";
                } else {
                    // ── SUCCESS: serve the file download ──
                    $tempPath = $dl['temp_path'];
                    $filename = $dl['filename'];
                    $mime     = $dl['mime'];

                    // Keep session token and temp file valid for the 10-minute window
                    // so users can refresh or re-download without error
                    session_write_close();

                    // Clean ALL output buffers
                    while (ob_get_level() > 0) {
                        ob_end_clean();
                    }

                    // Sanitize filename for Content-Disposition header
                    $safeFilename = preg_replace('/[^\w.\-\(\)\[\] ]/', '_', basename($filename));
                    if (empty($safeFilename) || $safeFilename === '.' || $safeFilename === '..') {
                        $safeFilename = 'decrypted_file';
                    }

                    // Send download headers
                    header('Content-Type: ' . $mime);
                    header('Content-Disposition: attachment; filename="' . $safeFilename . '"');
                    header('Content-Length: ' . $fileSize);
                    header('Cache-Control: no-store, no-cache, must-revalidate');
                    header('Pragma: no-cache');
                    header('Expires: 0');
                    header('X-Content-Type-Options: nosniff');

                    // Stream file to browser
                    readfile($tempPath);

                    exit;
                }
            }
        }
    }
    // If error, fall through to show the page
}

// ══════════════════════════════════════════════════════════════════════════════
// DECRYPT HANDLER — POST
// ══════════════════════════════════════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed. Please refresh and try again.";
    } else {
        $passphrase = $_POST['passphrase'] ?? '';

        if (empty($passphrase)) {
            $error = "Please enter the decryption passphrase.";
        } else {
            // Look up the encrypted file via the share record
            $db = Database::getInstance();
            $stmt = $db->prepare("
                SELECT f.stored_name, f.original_name, f.mime_type, f.id AS file_id
                FROM shares s
                JOIN files f ON s.file_id = f.id
                WHERE s.share_id = :share_id AND s.recipient_id = :recipient_id
            ");
            $stmt->execute([':share_id' => $shareId, ':recipient_id' => $userId]);
            $fileRow = $stmt->fetch();

            if (!$fileRow) {
                $error = "Share record not found.";
            } else {
                $encryptedPath = STORAGE_ENCRYPTED . '/' . $fileRow['stored_name'];

                if (!file_exists($encryptedPath)) {
                    $error = "Encrypted file not found on server.";
                } else {
                    $cipherBytes = @file_get_contents($encryptedPath);
                    if ($cipherBytes === false) {
                        $error = "Could not read encrypted file.";
                    } else {
                        // Attempt decryption with proper try-catch
                        try {
                            $decryptResult = AES256GCM::decryptFileContent($cipherBytes, $passphrase);
                        } catch (\Exception $e) {
                            $decryptResult = null;
                        }

                        if ($decryptResult === null) {
                            AuditLogger::logEvent(
                                $userId,
                                $user['username'],
                                'USER',
                                'SHARE',
                                'SHARE_FAILED',
                                null,
                                (int)$shareData['file_id'],
                                null,
                                'Recipient decrypt failed — wrong passphrase or corrupt data'
                            );
                            $error = "Decryption failed. Please check your passphrase and try again.";
                        } else {
                            // Decryption succeeded
                            AuditLogger::logEvent(
                                $userId,
                                $user['username'],
                                'USER',
                                'FILE',
                                'FILE_DECRYPTED',
                                null,
                                (int)$shareData['file_id'],
                                null,
                                'Recipient decrypted shared file'
                            );

                            $content      = $decryptResult['content'];
                            $originalName = $decryptResult['filename'] ?? $fileRow['original_name'];
                            $mimeType     = $decryptResult['mime'] ?? ($fileRow['mime_type'] ?: 'application/octet-stream');
                            $contentSize  = strlen($content);

                            if ($contentSize <= 0) {
                                $error = "Decryption completed, but the recovered file could not be prepared for download.";
                            } else {
                                // Write to temp file
                                $token    = bin2hex(random_bytes(32));
                                $tempName = 'dec_' . bin2hex(random_bytes(16)) . '.tmp';
                                $tempPath = STORAGE_TEMP . '/' . $tempName;

                                $written = @file_put_contents($tempPath, $content, LOCK_EX);

                                if ($written === false || $written !== $contentSize) {
                                    if (file_exists($tempPath)) @unlink($tempPath);
                                    $error = "Decryption completed, but the recovered file could not be prepared for download.";
                                } elseif (!file_exists($tempPath) || !is_readable($tempPath) || filesize($tempPath) !== $contentSize) {
                                    if (file_exists($tempPath)) @unlink($tempPath);
                                    $error = "Decryption completed, but the recovered file could not be prepared for download.";
                                } else {
                                    // Store download token in session
                                    if (!isset($_SESSION['decrypt_downloads'])) {
                                        $_SESSION['decrypt_downloads'] = [];
                                    }

                                    $_SESSION['decrypt_downloads'][$token] = [
                                        'temp_path'  => $tempPath,
                                        'filename'   => $originalName,
                                        'mime'       => $mimeType,
                                        'size'       => $contentSize,
                                        'user_id'    => $userId,
                                        'share_id'   => $shareId,
                                        'created_at' => time()
                                    ];

                                    $downloadReady = true;
                                    $downloadToken = $token;
                                    $downloadInfo  = [
                                        'filename' => $originalName,
                                        'mime'     => $mimeType,
                                        'size'     => $contentSize
                                    ];

                                    // Free memory
                                    unset($content, $decryptResult, $cipherBytes);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

$pageTitle = "Decrypt Shared File";
include BASE_DIR . '/templates/header.php';
?>

<div style="max-width: 620px; margin: 0 auto;">

    <div class="section-header">
        <div>
            <h1 class="section-title">🔓 Decrypt Shared File</h1>
            <p class="section-subtitle">Enter the passphrase to decrypt and download this file.</p>
        </div>
        <div>
            <a href="/received-shares.php" class="btn btn-secondary btn-inline">← Back</a>
        </div>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= sanitize($error) ?></div>
    <?php endif; ?>

    <?php if ($downloadReady && $downloadToken && $downloadInfo): ?>
        <!-- ═══════ DECRYPTION SUCCESS + DOWNLOAD ═══════ -->
        <div class="card" style="border-color: var(--success); text-align: center;">
            <div style="font-size: 3rem; margin-bottom: 12px;">✅</div>
            <h2 style="color: var(--success); margin-bottom: 8px; font-size: 1.4rem;">Decryption Successful</h2>
            <p style="color: var(--text-muted); margin-bottom: 20px;">
                The shared file has been successfully decrypted and is ready for download.
            </p>

            <div style="background-color: #0F172A; padding: 15px; border-radius: var(--radius); border: 1px solid var(--border-color); margin-bottom: 20px; text-align: left;">
                <div style="margin-bottom: 6px; display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted);">File Name:</span>
                    <strong><?= sanitize($downloadInfo['filename']) ?></strong>
                </div>
                <div style="margin-bottom: 6px; display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted);">Shared By:</span>
                    <strong><?= sanitize($shareData['sender_username']) ?></strong>
                </div>
                <div style="margin-bottom: 6px; display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted);">Type:</span>
                    <span><?= sanitize($downloadInfo['mime']) ?></span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted);">Size:</span>
                    <span><?= format_file_size($downloadInfo['size']) ?></span>
                </div>
            </div>

            <a href="/received-decrypt.php?share_id=<?= urlencode($shareId) ?>&download=<?= urlencode($downloadToken) ?>"
               class="btn btn-primary" style="width: 100%; font-size: 1.1rem; padding: 14px;">
                📥 Download Decrypted File
            </a>

            <div style="margin-top: 15px; font-size: 0.82rem; color: var(--text-muted);">
                ⏳ This download link expires in 10 minutes and can only be used once.
            </div>
        </div>

        <div style="text-align: center; margin-top: 15px;">
            <a href="/received-shares.php" class="btn btn-secondary">← Back to Received Files</a>
        </div>

    <?php else: ?>
        <!-- ═══════ FILE INFO + DECRYPT FORM ═══════ -->
        <div class="card" style="margin-bottom: 24px; border-color: var(--primary); background-color: #0F172A;">
            <h3 class="card-title" style="color: var(--primary); text-transform: none; font-size: 1.1rem;">
                📄 File Details
            </h3>
            <ul style="list-style: none; font-size: 0.9rem; margin: 0;">
                <li style="padding: 6px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                    <span style="color: var(--text-muted);">File Name:</span>
                    <strong><?= sanitize($shareData['original_name']) ?></strong>
                </li>
                <li style="padding: 6px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                    <span style="color: var(--text-muted);">Shared By:</span>
                    <strong><?= sanitize($shareData['sender_username']) ?></strong>
                </li>
                <li style="padding: 6px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                    <span style="color: var(--text-muted);">Encryption:</span>
                    <span style="color: var(--success); font-weight: 600;">AES-256-GCM</span>
                </li>
                <li style="padding: 6px 0; display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted);">Share Status:</span>
                    <span class="badge badge-<?= strtolower($shareData['status']) ?>"><?= sanitize($shareData['status']) ?></span>
                </li>
            </ul>
        </div>

        <!-- Passphrase Notice -->
        <div style="font-size: 0.88rem; color: var(--text-muted); background-color: rgba(99,102,241,0.08); padding: 12px 16px; border-radius: var(--radius); border: 1px solid rgba(99,102,241,0.25); margin-bottom: 24px;">
            🔑 <strong>Passphrase Required:</strong> The sender encrypted this file with a personal passphrase.
            You must obtain the passphrase from the sender through a secure channel.
            CipherShare does not store or transmit passphrases.
        </div>

        <!-- Decrypt Form -->
        <div class="card">
            <h3 class="card-title" style="text-transform: none; font-size: 1.05rem;">Enter Decryption Passphrase</h3>

            <form action="/received-decrypt.php?share_id=<?= urlencode($shareId) ?>" method="POST">
                <?= CSRF::getFormField() ?>

                <div class="form-group">
                    <label for="passphrase">Decryption Passphrase</label>
                    <input type="password" name="passphrase" id="passphrase" class="form-control"
                        required autocomplete="current-password"
                        placeholder="Enter the passphrase the sender gave you">
                </div>

                <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
                    <button type="submit" class="btn btn-primary">🔓 Decrypt File</button>
                    <a href="/received-shares.php" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
        </div>

        <div style="margin-top: 20px; font-size: 0.82rem; color: var(--text-muted); text-align: center;">
            🛡️ Your passphrase is used once for decryption and is never stored.
            The decrypted file is prepared temporarily for download and cleaned up automatically.
        </div>
    <?php endif; ?>

</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
