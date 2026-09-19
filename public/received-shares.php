<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Shares\ShareManager;
use Files\FileManager;

$user   = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error  = null;

// ── Raw .enc File Download Handler ───────────────────────────────────────────
if (isset($_GET['download_enc']) && !empty($_GET['download_enc'])) {
    $shareId = sanitize($_GET['download_enc']);
    $share   = ShareManager::accessShare($userId, $shareId, $error);

    if ($share) {
        $fileId   = $share['file_id'];
        $filePath = FileManager::getFilePath($userId, $fileId, true, $share['sender_id']);

        if ($filePath && file_exists($filePath)) {
            $baseName    = pathinfo($share['original_name'], PATHINFO_FILENAME);
            $encFileName = $baseName . '.enc';

            session_write_close();
            while (ob_get_level() > 0) { ob_end_clean(); }

            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . preg_replace('/[^\w.\-\(\)\[\] ]/', '_', $encFileName) . '"');
            header('Content-Length: ' . filesize($filePath));
            header('Cache-Control: no-store, no-cache, must-revalidate');
            header('Pragma: no-cache');
            header('X-Content-Type-Options: nosniff');
            readfile($filePath);
            exit;
        } else {
            $error = "Encrypted container file is missing on storage.";
        }
    }
}

// ── Plaintext Download Handler ───────────────────────────────────────────────
if (isset($_GET['access']) && !empty($_GET['access'])) {
    $shareId = sanitize($_GET['access']);
    $share   = ShareManager::accessShare($userId, $shareId, $error);

    if ($share) {
        if ($share['is_encrypted']) {
            redirect('/received-decrypt.php?share_id=' . urlencode($shareId));
        }
        $fileId   = $share['file_id'];
        $filePath = FileManager::getFilePath($userId, $fileId, true, $share['sender_id']);

        if ($filePath && file_exists($filePath)) {
            $fileName = $share['original_name'];
            session_write_close();
            while (ob_get_level() > 0) { ob_end_clean(); }
            header('Content-Type: ' . ($share['mime_type'] ?: 'application/octet-stream'));
            header('Content-Disposition: attachment; filename="' . preg_replace('/[^\w.\-\(\)\[\] ]/', '_', $fileName) . '"');
            header('Content-Length: ' . filesize($filePath));
            header('Cache-Control: no-store, no-cache, must-revalidate');
            header('X-Content-Type-Options: nosniff');
            readfile($filePath);
            exit;
        } else {
            $error = "Target file could not be found on the server.";
        }
    }
}

$receivedShares = ShareManager::getReceivedShares($userId);

$pageTitle = "Received Shares";
include BASE_DIR . '/templates/header.php';
?>

<div style="margin-bottom: 24px;">
    <h1 style="font-size: 1.8rem; color: var(--text-main); margin-bottom: 4px;">📥 Received Shares</h1>
    <p style="color: var(--text-muted);">Files securely shared with you by other users.</p>
</div>

<?php if ($error): ?>
    <div class="alert alert-danger">⚠️ <?= sanitize($error) ?></div>
<?php endif; ?>

<?php if (empty($receivedShares)): ?>
    <div class="empty-state">
        <div class="empty-state-icon">📥</div>
        <p>No shared files received yet.</p>
        <small>When another CipherShare user sends you a file, it will appear here.</small>
    </div>
<?php else: ?>
    <div class="card-grid">
        <?php foreach ($receivedShares as $s): ?>
            <div class="card" style="display: flex; flex-direction: column; justify-content: space-between; gap: 16px;">
                <div>
                    <!-- Header with filename and status badge -->
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; gap: 10px;">
                        <div>
                            <div style="font-size: 1.1rem; font-weight: 700; color: var(--text-main); word-break: break-all;">
                                <?php if ($s['is_encrypted']): ?>
                                    🔐 <?= sanitize($s['original_name']) ?> <span style="font-size: 0.8rem; color: var(--primary); font-family: monospace;">(.enc)</span>
                                <?php else: ?>
                                    📄 <?= sanitize($s['original_name']) ?>
                                <?php endif; ?>
                            </div>
                        </div>
                        <div>
                            <?php if ($s['status'] === 'PENDING'): ?>
                                <span class="badge badge-pending">PENDING</span>
                            <?php elseif ($s['status'] === 'SUCCESS'): ?>
                                <span class="badge badge-success">ACCESSED</span>
                            <?php elseif ($s['status'] === 'FAILED' || $s['status'] === 'EXPIRED'): ?>
                                <span class="badge badge-failed">EXPIRED</span>
                            <?php elseif ($s['status'] === 'CANCELLED'): ?>
                                <span class="badge badge-cancelled">CANCELLED</span>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Details -->
                    <ul style="list-style: none; font-size: 0.88rem; margin-bottom: 14px;">
                        <li style="padding: 5px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                            <span style="color: var(--text-muted);">From:</span>
                            <strong>👤 <?= sanitize($s['sender_username']) ?></strong>
                        </li>
                        <li style="padding: 5px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                            <span style="color: var(--text-muted);">Format:</span>
                            <?php if ($s['is_encrypted']): ?>
                                <span class="badge badge-success">🔐 AES-256-GCM Container</span>
                            <?php else: ?>
                                <span class="badge badge-cancelled">Plaintext</span>
                            <?php endif; ?>
                        </li>
                        <li style="padding: 5px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                            <span style="color: var(--text-muted);">Shared:</span>
                            <span style="color: var(--text-main);"><?= date('d M Y, h:i A', strtotime($s['created_at'])) ?></span>
                        </li>
                        <li style="padding: 5px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                            <span style="color: var(--text-muted);">Expires:</span>
                            <span style="color: var(--warning); font-weight: 600;"><?= date('d M Y, h:i A', strtotime($s['expires_at'])) ?></span>
                        </li>
                    </ul>

                    <!-- Status Description -->
                    <div style="font-size: 0.84rem; padding: 10px 12px; border-radius: 8px; background: var(--bg-main); border: 1px solid var(--border-color);">
                        <?php if ($s['status'] === 'PENDING' || $s['status'] === 'SUCCESS'): ?>
                            <?php if ($s['is_encrypted']): ?>
                                <div style="color: var(--text-muted);">
                                    🔐 Encrypted container file. You can download the raw <code>.enc</code> file directly or decrypt it separately with the passphrase.
                                </div>
                            <?php else: ?>
                                <div style="color: var(--text-muted);">
                                    📄 Plaintext shared file. Download it directly before expiration.
                                </div>
                            <?php endif; ?>
                        <?php else: ?>
                            <div style="color: var(--danger);">
                                ⚠️ Share link expired or no longer available.
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Action Buttons -->
                <div>
                    <?php if ($s['status'] === 'PENDING' || $s['status'] === 'SUCCESS'): ?>
                        <?php if ($s['is_encrypted']): ?>
                            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                                <!-- Download Raw .enc file -->
                                <a href="/received-shares.php?download_enc=<?= urlencode($s['share_id']) ?>"
                                   class="btn btn-secondary btn-sm" style="flex: 1; min-width: 140px; text-align: center;">
                                    ⬇ Download .enc
                                </a>
                                <!-- Separate Decrypt Page -->
                                <a href="/received-decrypt.php?share_id=<?= urlencode($s['share_id']) ?>"
                                   class="btn btn-primary btn-sm" style="flex: 1; min-width: 140px; text-align: center;">
                                    🔓 Decrypt File
                                </a>
                            </div>
                        <?php else: ?>
                            <a href="/received-shares.php?access=<?= urlencode($s['share_id']) ?>" class="btn btn-primary btn-sm" style="width: 100%;">
                                ⬇ Download File
                            </a>
                        <?php endif; ?>
                    <?php else: ?>
                        <button disabled class="btn btn-secondary btn-sm" style="width: 100%; opacity: 0.5; cursor: not-allowed;">
                            No Longer Available
                        </button>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<?php include BASE_DIR . '/templates/footer.php'; ?>
