<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Shares\ShareManager;
use Security\CSRF;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;
$downloadReady = false;
$downloadToken = null;
$downloadInfo = null;

// ── CLEANUP: purge expired download tokens (older than 10 minutes) ───────────
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

// ══════════════════════════════════════════════════════════════════════════════
// DOWNLOAD HANDLER — GET ?download=TOKEN
// Streams the decrypted temp file. Token remains valid for the 10-minute window.
// ══════════════════════════════════════════════════════════════════════════════
if (isset($_GET['download']) && !empty($_GET['download'])) {
    $token = $_GET['download'];

    if (!isset($_SESSION['decrypt_downloads'][$token])) {
        $error = "Download link has expired or is invalid. Please decrypt the file again.";
    } else {
        $dl = $_SESSION['decrypt_downloads'][$token];

        if ((int)($dl['user_id'] ?? 0) !== $userId) {
            $error = "Access denied.";
        } elseif (time() - ($dl['created_at'] ?? 0) > 600) {
            if (!empty($dl['temp_path']) && file_exists($dl['temp_path'])) {
                @unlink($dl['temp_path']);
            }
            unset($_SESSION['decrypt_downloads'][$token]);
            $error = "Download link has expired. Please decrypt the file again.";
        } elseif (empty($dl['temp_path']) || !file_exists($dl['temp_path']) || !is_file($dl['temp_path']) || !is_readable($dl['temp_path'])) {
            $error = "Decrypted file is no longer available. Please decrypt again.";
        } else {
            // Path security: verify temp file is strictly inside STORAGE_TEMP
            $realPath = realpath($dl['temp_path']);
            $realTemp = realpath(STORAGE_TEMP);
            if ($realPath === false || $realTemp === false || strpos($realPath, $realTemp) !== 0) {
                $error = "Download failed due to a security check.";
            } else {
                $fileSize = filesize($dl['temp_path']);
                if ($fileSize === false || $fileSize <= 0) {
                    $error = "Decrypted file appears to be empty or corrupted.";
                } else {
                    // ── SUCCESS: serve the file download ──
                    $tempPath = $dl['temp_path'];
                    $filename = $dl['filename'];
                    $mime     = $dl['mime'];

                    // Close session to release lock during streaming
                    session_write_close();

                    // Clean ALL output buffers to prevent binary corruption
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
}

// ══════════════════════════════════════════════════════════════════════════════
// DECRYPT HANDLER — POST
// Decrypts the file, writes to temp, stores download token in session.
// ══════════════════════════════════════════════════════════════════════════════
$fileId = isset($_POST['file_id']) ? (int)$_POST['file_id'] : (isset($_GET['file_id']) ? (int)$_GET['file_id'] : 0);
$file = $fileId > 0 ? FileManager::getUserFile($userId, $fileId) : null;

// Also load all user files and received shares for selection
$userFiles = FileManager::getUserFiles($userId);
$encryptedFiles = array_filter($userFiles, fn($f) => !empty($f['is_encrypted']));

$receivedShares = ShareManager::getReceivedShares($userId);
$encryptedReceivedShares = array_filter($receivedShares, fn($s) => !empty($s['is_encrypted']) && in_array($s['status'], ['PENDING', 'SUCCESS']));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } elseif (!$file) {
        $error = "Please select an encrypted file to decrypt.";
    } else {
        $passphrase = $_POST['passphrase'] ?? '';
        if (empty($passphrase)) {
            $error = "Please enter your decryption passphrase.";
        } else {
            $decrypted = FileManager::decryptUserFile($userId, $fileId, $passphrase, $error);

            if ($decrypted) {
                $content     = $decrypted['content'];
                $filename    = $decrypted['filename'] ?? $file['original_name'];
                $mime        = $decrypted['mime'] ?? ($file['mime_type'] ?: 'application/octet-stream');
                $contentSize = strlen($content);

                if ($contentSize <= 0) {
                    $error = "Decryption completed, but the recovered file could not be prepared for download.";
                } else {
                    // Write decrypted content to a secure temporary file
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
                            'filename'   => $filename,
                            'mime'       => $mime,
                            'size'       => $contentSize,
                            'user_id'    => $userId,
                            'file_id'    => $fileId,
                            'created_at' => time()
                        ];

                        $downloadReady = true;
                        $downloadToken = $token;
                        $downloadInfo  = [
                            'filename' => $filename,
                            'mime'     => $mime,
                            'size'     => $contentSize
                        ];

                        // Free decrypted content from memory
                        unset($content, $decrypted);
                    }
                }
            }
        }
    }
}

$pageTitle = "Decrypt File";
include BASE_DIR . '/templates/header.php';
?>

<div style="max-width: 680px; margin: 0 auto;">

    <div class="section-header">
        <div>
            <h1 class="section-title">🔓 Decrypt File</h1>
            <p class="section-subtitle">Decrypt an AES-256-GCM encrypted file and download the original.</p>
        </div>
        <div>
            <a href="/files.php" class="btn btn-secondary btn-inline">← My Files</a>
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
                Your file has been successfully recovered and is ready for download.
            </p>

            <div style="background-color: #0F172A; padding: 15px; border-radius: var(--radius); border: 1px solid var(--border-color); margin-bottom: 20px; text-align: left;">
                <div style="margin-bottom: 6px; display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted);">File Name:</span>
                    <strong><?= sanitize($downloadInfo['filename']) ?></strong>
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

            <a href="/decrypt.php?download=<?= urlencode($downloadToken) ?>"
               class="btn btn-primary" style="width: 100%; font-size: 1.1rem; padding: 14px;">
                📥 Download Decrypted File
            </a>

            <div style="margin-top: 15px; font-size: 0.82rem; color: var(--text-muted);">
                ⏳ This download link expires in 10 minutes and can be downloaded multiple times during this period.
            </div>
        </div>

        <div style="text-align: center; margin-top: 15px;">
            <a href="/files.php" class="btn btn-secondary">← Back to My Files</a>
        </div>

    <?php elseif ($file && $file['is_encrypted']): ?>
        <!-- ═══════ SINGLE FILE SELECTED DECRYPT FORM ═══════ -->
        <div class="card" style="border-color: var(--primary); margin-bottom: 20px; background-color: #0F172A;">
            <h3 class="card-title" style="color: var(--primary); text-transform: none; font-size: 1.1rem;">
                📄 Selected File Details
            </h3>
            <ul style="list-style: none; font-size: 0.9rem; margin: 0;">
                <li style="padding: 6px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                    <span style="color: var(--text-muted);">File Name:</span>
                    <strong><?= sanitize($file['original_name']) ?></strong>
                </li>
                <li style="padding: 6px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                    <span style="color: var(--text-muted);">Algorithm:</span>
                    <span style="color: var(--success); font-weight: 600;"><?= sanitize($file['cipher_alg'] ?? 'AES-256-GCM') ?></span>
                </li>
                <li style="padding: 6px 0; display: flex; justify-content: space-between;">
                    <span style="color: var(--text-muted);">Container Size:</span>
                    <span><?= format_file_size($file['file_size']) ?></span>
                </li>
            </ul>
        </div>

        <div class="card">
            <h3 class="card-title" style="text-transform: none; font-size: 1.05rem;">Enter Decryption Passphrase</h3>

            <form action="/decrypt.php?file_id=<?= $file['id'] ?>" method="POST">
                <?= CSRF::getFormField() ?>
                <input type="hidden" name="file_id" value="<?= $file['id'] ?>">

                <div class="form-group">
                    <label for="passphrase">Decryption Passphrase</label>
                    <input type="password" name="passphrase" id="passphrase" class="form-control"
                        required autocomplete="off"
                        placeholder="Passphrase used during encryption">
                </div>

                <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
                    <button type="submit" class="btn btn-primary">🔓 Decrypt File</button>
                    <a href="/decrypt.php" class="btn btn-secondary">Choose Different File</a>
                </div>
            </form>
        </div>

        <div style="margin-top: 15px; font-size: 0.82rem; color: var(--text-muted); text-align: center;">
            🛡️ Your passphrase is used once for decryption and is never stored.
            The decrypted file is prepared temporarily for download and cleaned up automatically.
        </div>

    <?php elseif (!empty($encryptedFiles)): ?>
        <!-- ═══════ CHOOSE FROM ENCRYPTED FILES ═══════ -->
        <div class="card">
            <h3 class="card-title" style="text-transform: none; font-size: 1.1rem; color: var(--primary);">
                🔐 Select an Encrypted File to Decrypt
            </h3>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 20px;">
                Choose one of your AES-256-GCM encrypted files and enter the passphrase to decrypt it.
            </p>

            <form action="/decrypt.php" method="POST">
                <?= CSRF::getFormField() ?>

                <div class="form-group">
                    <label for="file_id">Select File</label>
                    <select name="file_id" id="file_id" class="form-control" required>
                        <option value="">-- Choose an Encrypted File --</option>
                        <?php foreach ($encryptedFiles as $ef): ?>
                            <option value="<?= $ef['id'] ?>" <?= $ef['id'] === $fileId ? 'selected' : '' ?>>
                                📄 <?= sanitize($ef['original_name']) ?> (<?= format_file_size($ef['file_size']) ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-group">
                    <label for="passphrase">Decryption Passphrase</label>
                    <input type="password" name="passphrase" id="passphrase" class="form-control"
                        required autocomplete="off"
                        placeholder="Passphrase used during encryption">
                </div>

                <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
                    <button type="submit" class="btn btn-primary">🔓 Decrypt File</button>
                    <a href="/files.php" class="btn btn-secondary">Cancel</a>
                </div>
            </form>
        </div>

    <?php else: ?>
        <!-- ═══════ NO OWNED ENCRYPTED FILES ═══════ -->
        <div class="card" style="text-align: center; margin-bottom: 20px;">
            <div style="font-size: 2.5rem; margin-bottom: 12px;">📁</div>
            <h3 style="font-size: 1.2rem; margin-bottom: 8px;">No Encrypted Files Found</h3>
            <p style="color: var(--text-muted); margin-bottom: 15px;">
                You don't have any encrypted files in your account yet.
            </p>
            <div style="display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">
                <a href="/upload.php" class="btn btn-primary">+ Upload New File</a>
                <a href="/files.php" class="btn btn-secondary">Go to My Files</a>
            </div>
        </div>
    <?php endif; ?>

    <!-- ═══════ RECEIVED ENCRYPTED SHARES SECTION ═══════ -->
    <?php if (!empty($encryptedReceivedShares)): ?>
        <div class="card" style="margin-top: 25px; border-color: var(--border-color);">
            <h3 class="card-title" style="text-transform: none; font-size: 1.1rem; color: var(--text-main);">
                📥 Received Encrypted Files from Other Users
            </h3>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 15px;">
                The following encrypted files were shared with your account. Click to decrypt with the passphrase provided by the sender.
            </p>
            <div style="display: flex; flex-direction: column; gap: 10px;">
                <?php foreach ($encryptedReceivedShares as $rs): ?>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background-color: #0F172A; border-radius: var(--radius); border: 1px solid var(--border-color); flex-wrap: wrap; gap: 10px;">
                        <div>
                            <div style="font-weight: 600; color: var(--text-main);">📄 <?= sanitize($rs['original_name']) ?></div>
                            <div style="font-size: 0.82rem; color: var(--text-muted);">
                                From: <strong><?= sanitize($rs['sender_username']) ?></strong> &bull;
                                Expires: <?= date('d M, h:i A', strtotime($rs['expires_at'])) ?>
                            </div>
                        </div>
                        <a href="/received-decrypt.php?share_id=<?= urlencode($rs['share_id']) ?>" class="btn btn-primary btn-sm">
                            🔓 Decrypt Shared File
                        </a>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
