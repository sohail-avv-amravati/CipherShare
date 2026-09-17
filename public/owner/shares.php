<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Owner\OwnerManager;
use Database\Database;

$owner = AuthManager::requireOwner();
$stats = OwnerManager::getDashboardStats();

$db = Database::getInstance();
$stmtShares = $db->query("
    SELECT s.*, f.original_name, u1.username AS sender_name, u2.username AS recipient_name
    FROM shares s
    JOIN files f ON s.file_id = f.id
    JOIN users u1 ON s.sender_id = u1.id
    JOIN users u2 ON s.recipient_id = u2.id
    ORDER BY s.created_at DESC
    LIMIT 100
");
$recentShares = $stmtShares->fetchAll(\PDO::FETCH_ASSOC);

$pageTitle = "Share Statistics";
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div style="margin-bottom: 25px;">
    <h1 style="font-size: 1.8rem; color: var(--warning);">Share Statistics & Expiration Overview</h1>
    <p style="color: var(--text-muted);">Monitor platform file sharing activity and server expiration transitions.</p>
</div>

<div class="card-grid">
    <div class="card">
        <div class="card-title">Total Shares Created</div>
        <div class="stat-number"><?= $stats['shares']['total'] ?></div>
    </div>
    <div class="card">
        <div class="card-title">Pending Active Shares</div>
        <div class="stat-number" style="color: var(--warning);"><?= $stats['shares']['pending'] ?></div>
    </div>
    <div class="card">
        <div class="card-title">Successful Accessed Shares</div>
        <div class="stat-number" style="color: var(--success);"><?= $stats['shares']['success'] ?></div>
    </div>
    <div class="card">
        <div class="card-title">Failed / Expired Shares</div>
        <div class="stat-number" style="color: var(--danger);"><?= $stats['shares']['failed'] ?></div>
    </div>
</div>

<div class="card">
    <h3 class="card-title">Recent Shares Activity Log</h3>
    <div class="table-responsive" style="margin-top: 15px;">
        <table>
            <thead>
                <tr>
                    <th>Share ID</th>
                    <th>Sender</th>
                    <th>Recipient</th>
                    <th>File Name</th>
                    <th>Created At</th>
                    <th>Expires At</th>
                    <th>Status</th>
                    <th>Failure Reason</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentShares as $rs): ?>
                    <tr>
                        <td style="font-size: 0.85rem; font-family: monospace;"><?= sanitize(substr($rs['share_id'], 0, 10)) ?>...</td>
                        <td><?= sanitize($rs['sender_name']) ?></td>
                        <td><?= sanitize($rs['recipient_name']) ?></td>
                        <td style="font-weight: 600;"><?= sanitize($rs['original_name']) ?></td>
                        <td style="font-size: 0.85rem; color: var(--text-muted);"><?= sanitize($rs['created_at']) ?></td>
                        <td style="font-size: 0.85rem; color: var(--text-muted);"><?= sanitize($rs['expires_at']) ?></td>
                        <td>
                            <?php if ($rs['status'] === 'PENDING'): ?>
                                <span class="badge badge-pending">PENDING</span>
                            <?php elseif ($rs['status'] === 'SUCCESS'): ?>
                                <span class="badge badge-success">SUCCESS</span>
                            <?php elseif ($rs['status'] === 'FAILED' || $rs['status'] === 'EXPIRED'): ?>
                                <span class="badge badge-failed">FAILED / EXPIRED</span>
                            <?php else: ?>
                                <span class="badge badge-cancelled">CANCELLED</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-size: 0.85rem; color: var(--danger);"><?= sanitize($rs['failure_reason'] ?? '-') ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
