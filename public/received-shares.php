<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Shares\ShareManager;
use Files\FileManager;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;

// Handle File Download (Accessing a share)
if (isset($_GET['access'])) {
    $shareId = $_GET['access'];
    $share = ShareManager::accessShare($userId, $shareId, $error);
    
    if ($share) {
        $fileId = $share['file_id'];
        $filePath = FileManager::getFilePath($userId, $fileId, true, $share['sender_id']);
        
        if ($filePath && file_exists($filePath)) {
            $fileName = $share['original_name'];
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $fileName . '"');
            header('Content-Length: ' . filesize($filePath));
            readfile($filePath);
            exit;
        } else {
            $error = "Target file could not be found on the server.";
        }
    }
}

$viewShareData = null;
if (isset($_GET['view'])) {
    $shareId = $_GET['view'];
    foreach (ShareManager::getReceivedShares($userId) as $s) {
        if ($s['share_id'] === $shareId && $s['status'] === 'PENDING') {
            $viewShareData = $s;
            break;
        }
    }
    if (!$viewShareData) {
        $error = "Share link is invalid, expired, or you do not have permission.";
    }
}

$receivedShares = ShareManager::getReceivedShares($userId);

$pageTitle = "Received Shares";
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">?? Received Shares</h1>
        <p class="section-subtitle">Files securely shared with you by other users.</p>
    </div>
</div>

<?php if ($error): ?>
    <div class="alert alert-danger"><?= sanitize($error) ?></div>
<?php endif; ?>

<?php if ($viewShareData): ?>
    <div class="card" style="margin-bottom: 30px; border: 2px solid var(--primary); background: rgba(99, 102, 241, 0.05);">
        <h3 class="card-title" style="color: var(--primary);">?? Access Shared File</h3>
        <p style="margin-bottom: 20px;">
            User <strong><?= sanitize($viewShareData['sender_username']) ?></strong> has shared a file with you.
        </p>
        
        <div style="background: var(--bg-color); padding: 15px; border-radius: var(--radius); margin-bottom: 20px; font-family: monospace;">
            File: <?= sanitize($viewShareData['original_name']) ?><br>
            Expires: <?= date('d M Y, h:i A', strtotime($viewShareData['expires_at'])) ?>
        </div>

        <?php if ($viewShareData['is_encrypted']): ?>
        <div class="alert alert-warning">
            ?? This file is encrypted. You will need the passphrase from the sender to decrypt it.
        </div>
        <?php endif; ?>

        <div style="display: flex; gap: 12px;">
            <a href="/received-shares.php" class="btn btn-secondary" style="flex: 1;">Cancel</a>
            <?php if ($viewShareData['is_encrypted']): ?>
                <a href="/received-decrypt.php?share_id=<?= urlencode($viewShareData['share_id']) ?>" class="btn btn-primary" style="flex: 2;">
                    ?? Decrypt &amp; Download
                </a>
            <?php else: ?>
                <a href="/received-shares.php?access=<?= sanitize($viewShareData['share_id']) ?>" class="btn btn-primary" style="flex: 2;">
                    OPEN SHARED FILE
                </a>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<!-- RECEIVED SHARES CARDS LISTING -->
<?php if (empty($receivedShares)): ?>
    <div class="empty-state">
        <div class="empty-state-icon">??</div>
        <div class="empty-state-text">No shared files yet</div>
        <div class="empty-state-sub">When another CipherShare user sends you a file, it will appear here.</div>
    </div>
<?php else: ?>
    <div class="card-grid">
        <?php foreach ($receivedShares as $s): ?>
            <div class="card" style="display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; gap: 10px;">
                        <div style="font-size: 1.1rem; font-weight: 700; color: var(--text-main); word-break: break-word;">
                            ?? <?= sanitize($s['original_name']) ?>
                        </div>
                        <div>
                            <?php if ($s['status'] === 'PENDING'): ?>
                                <span class="badge badge-pending">PENDING</span>
                            <?php elseif ($s['status'] === 'SUCCESS'): ?>
                                <span class="badge badge-success">SUCCESS</span>
                            <?php elseif ($s['status'] === 'FAILED' || $s['status'] === 'EXPIRED'): ?>
                                <span class="badge badge-failed">EXPIRED</span>
                            <?php elseif ($s['status'] === 'CANCELLED'): ?>
                                <span class="badge badge-cancelled">CANCELLED</span>
                            <?php endif; ?>
                        </div>
                    </div>

                    <ul style="list-style: none; font-size: 0.9rem; margin-bottom: 15px;">
                        <li style="padding: 4px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                            <span style="color: var(--text-muted);">From:</span>
                            <strong><?= sanitize($s['sender_username']) ?></strong>
                        </li>
                        <li style="padding: 4px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                            <span style="color: var(--text-muted);">Shared:</span>
                            <span style="color: var(--text-main);"><?= date('d M Y, h:i A', strtotime($s['created_at'])) ?></span>
                        </li>
                        <li style="padding: 4px 0; display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border-color);">
                            <span style="color: var(--text-muted);">Available Until:</span>
                            <span style="color: var(--primary); font-weight: 600;"><?= date('d M Y, h:i A', strtotime($s['expires_at'])) ?></span>
                        </li>
                        <?php if ($s['status'] === 'SUCCESS' && !empty($s['accessed_at'])): ?>
                            <li style="padding: 4px 0; display: flex; justify-content: space-between;">
                                <span style="color: var(--text-muted);">Access Time:</span>
                                <span style="color: var(--success); font-weight: 500;"><?= date('d M Y, h:i A', strtotime($s['accessed_at'])) ?></span>
                            </li>
                        <?php endif; ?>
                    </ul>

                    <!-- STATUS SPECIFIC DESCRIPTION & MESSAGES -->
                    <div style="font-size: 0.88rem; margin-bottom: 18px; padding: 10px; border-radius: var(--radius); background-color: var(--bg-color); border: 1px solid var(--border-color);">
                        <?php if ($s['status'] === 'PENDING'): ?>
                            <p style="color: var(--text-muted); margin-bottom: 8px;">
                                ?? This file was securely shared with you. Access it before the expiration time to complete the transfer.
                            </p>
                            <div style="font-size: 0.78rem; color: var(--success);">
                                ??? <strong>SECURE SHARE:</strong> Only the intended recipient can access this shared file.
                            </div>
                        <?php elseif ($s['status'] === 'SUCCESS'): ?>
                            <p style="color: var(--success);">
                                ? You accessed this shared file before the deadline. The share was completed successfully.
                            </p>
                        <?php elseif ($s['status'] === 'FAILED' || $s['status'] === 'EXPIRED'): ?>
                            <p style="color: var(--danger); margin-bottom: 4px;">
                                ?? <strong>Share expired:</strong> The access deadline for this file has passed. The file can no longer be accessed through this share.
                            </p>
                            <div style="font-size: 0.8rem; color: var(--text-muted);">
                                This shared file is no longer available because its access deadline has passed.
                            </div>
                        <?php elseif ($s['status'] === 'CANCELLED'): ?>
                            <p style="color: var(--text-muted);">
                                ?? This share was cancelled by the sender and is no longer available.
                            </p>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- ACTION BUTTONS -->
                <div>
                    <?php if ($s['status'] === 'PENDING'): ?>
                        <a href="/received-shares.php?view=<?= sanitize($s['share_id']) ?>" class="btn btn-primary" style="width: 100%;">
                            OPEN FILE
                        </a>
                    <?php elseif ($s['status'] === 'SUCCESS'): ?>
                        <?php if ($s['is_encrypted']): ?>
                            <a href="/received-decrypt.php?share_id=<?= urlencode($s['share_id']) ?>" class="btn btn-primary btn-sm" style="width: 100%;">
                                ?? Decrypt &amp; Download
                            </a>
                        <?php else: ?>
                            <a href="/received-shares.php?access=<?= sanitize($s['share_id']) ?>" class="btn btn-secondary btn-sm" style="width: 100%;">
                                DOWNLOAD AGAIN
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
