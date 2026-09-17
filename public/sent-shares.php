<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Shares\ShareManager;
use Security\CSRF;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'cancel') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        $shareId = $_POST['share_id'] ?? '';
        if (ShareManager::cancelShare($userId, $shareId, $error)) {
            set_flash_message('info', 'Share has been cancelled.');
            redirect('/sent-shares.php');
        }
    }
}

$sentShares = ShareManager::getSentShares($userId);

$pageTitle = "Sent Shares";
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">?? Sent Secure Shares</h1>
        <p class="section-subtitle">Track real-time status and server expiration of files shared with recipients.</p>
    </div>
    <div>
        <a href="/shares.php" class="btn btn-primary btn-inline">+ Share Another File</a>
        <a href="/received-shares.php" class="btn btn-secondary btn-inline">Received Shares</a>
    </div>
</div>

<?php if ($error): ?>
    <div class="alert alert-danger"><?= sanitize($error) ?></div>
<?php endif; ?>

<?php if (empty($sentShares)): ?>
    <div class="empty-state">
        <div class="empty-state-icon">??</div>
        <div class="empty-state-text">No sent shares recorded yet.</div>
        <div class="empty-state-sub"><a href="/shares.php">Share a file with another user now</a>.</div>
    </div>
<?php else: ?>
    <div class="table-responsive">
        <table>
            <thead>
                <tr>
                    <th>File Name</th>
                    <th>Recipient</th>
                    <th>Created At</th>
                    <th>Expires At</th>
                    <th>Status</th>
                    <th>Accessed At</th>
                    <th>Reason / Details</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($sentShares as $s): ?>
                    <tr>
                        <td style="font-weight: 600;">
                            <?= sanitize($s['original_name']) ?>
                            <?= $s['is_encrypted'] ? ' <span class="badge badge-success">Encrypted</span>' : '' ?>
                        </td>
                        <td><strong><?= sanitize($s['recipient_username']) ?></strong></td>
                        <td style="font-size: 0.85rem; color: var(--text-muted); white-space: nowrap;"><?= date('d M Y, h:i A', strtotime($s['created_at'])) ?></td>
                        <td style="font-size: 0.85rem; color: var(--text-muted); white-space: nowrap;"><?= date('d M Y, h:i A', strtotime($s['expires_at'])) ?></td>
                        <td>
                            <?php if ($s['status'] === 'PENDING'): ?>
                                <span class="badge badge-pending">PENDING</span>
                            <?php elseif ($s['status'] === 'SUCCESS'): ?>
                                <span class="badge badge-success">SUCCESS</span>
                            <?php elseif ($s['status'] === 'FAILED' || $s['status'] === 'EXPIRED'): ?>
                                <span class="badge badge-failed">EXPIRED</span>
                            <?php elseif ($s['status'] === 'CANCELLED'): ?>
                                <span class="badge badge-cancelled">CANCELLED</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-size: 0.85rem; color: var(--text-muted); white-space: nowrap;">
                            <?= $s['accessed_at'] ? date('d M Y, h:i A', strtotime($s['accessed_at'])) : 'Not accessed' ?>
                        </td>
                        <td style="font-size: 0.85rem; color: var(--danger);">
                            <?= sanitize($s['failure_reason'] ?? '-') ?>
                        </td>
                        <td>
                            <?php if ($s['status'] === 'PENDING'): ?>
                                <form action="/sent-shares.php" method="POST" style="display: inline;">
                                    <?= CSRF::getFormField() ?>
                                    <input type="hidden" name="action" value="cancel">
                                    <input type="hidden" name="share_id" value="<?= sanitize($s['share_id']) ?>">
                                    <button type="submit" class="btn btn-danger btn-sm">Cancel</button>
                                </form>
                            <?php else: ?>
                                <span style="color: var(--text-muted); font-size: 0.85rem;">-</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>

<?php include BASE_DIR . '/templates/footer.php'; ?>
