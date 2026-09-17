<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Owner\OwnerManager;

$owner = AuthManager::requireOwner();
$stats = OwnerManager::getDashboardStats();
$recentLogs = OwnerManager::getAuditLogsFiltered([], 1, 5)['items'];

$pageTitle = "Owner Dashboard";
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">👑 CipherShare Owner Dashboard</h1>
        <p class="section-subtitle">Welcome, <?= sanitize($owner['username']) ?>. Real-time platform metrics and audit overview.</p>
    </div>
</div>

<!-- PLATFORM OVERVIEW -->
<div style="margin-bottom: 30px;">
    <h2 style="font-size: 1.1rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 15px;">PLATFORM OVERVIEW</h2>
    <div class="card-grid">
        <div class="card">
            <div class="card-title">👥 Users</div>
            <div class="stat-number"><?= $stats['users']['total'] ?></div>
            <p class="stat-desc">Active: <?= $stats['users']['active'] ?> | Suspended: <?= $stats['users']['suspended'] ?></p>
        </div>

        <div class="card">
            <div class="card-title">📁 Files</div>
            <div class="stat-number"><?= $stats['files']['total'] ?></div>
            <p class="stat-desc">Encrypted: <?= $stats['files']['encrypted'] ?> (<?= $stats['files']['storage_formatted'] ?>)</p>
        </div>

        <div class="card">
            <div class="card-title">📤 Shared</div>
            <div class="stat-number"><?= $stats['shares']['total'] ?></div>
            <p class="stat-desc">Pending: <?= $stats['shares']['pending'] ?> | Success: <?= $stats['shares']['success'] ?></p>
        </div>

        <div class="card">
            <div class="card-title">📈 Success Rate</div>
            <div class="stat-number" style="color: var(--success);"><?= $stats['shares']['success_rate'] ?>%</div>
            <p class="stat-desc">Share completion efficiency</p>
        </div>
    </div>
</div>

<!-- QUICK ACTIONS -->
<div style="margin-bottom: 30px;">
    <h2 style="font-size: 1.1rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 15px;">QUICK ACTIONS</h2>
    <div class="action-grid">
        <a href="/owner/users.php" class="action-card">
            <span class="action-icon">👥</span>
            <strong>Manage Users</strong>
        </a>
        <a href="/owner/shares.php" class="action-card">
            <span class="action-icon">📤</span>
            <strong>View Shares</strong>
        </a>
        <a href="/owner/security.php" class="action-card">
            <span class="action-icon">🛡️</span>
            <strong>Security Center</strong>
        </a>
        <a href="/owner/audit.php" class="action-card">
            <span class="action-icon">📋</span>
            <strong>Audit Logs</strong>
        </a>
    </div>
</div>

<!-- RECENT ACTIVITY -->
<div style="margin-bottom: 30px;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <h2 style="font-size: 1.1rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;">RECENT ACTIVITY</h2>
        <a href="/owner/audit.php" style="font-size: 0.85rem;">View All Logs &rarr;</a>
    </div>

    <?php if (empty($recentLogs)): ?>
        <div class="empty-state">
            <div class="empty-state-icon">📋</div>
            <div class="empty-state-text">No activity recorded yet.</div>
            <div class="empty-state-sub">Application events will be logged here in real time.</div>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Event</th>
                        <th>Actor</th>
                        <th>Description</th>
                        <th>Date / Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recentLogs as $log): 
                        $cat = strtolower($log['event_category'] ?? 'general');
                    ?>
                        <tr>
                            <td><span class="badge badge-<?= $cat ?>"><?= sanitize($log['event_category']) ?></span></td>
                            <td><strong><?= sanitize($log['event_type']) ?></strong></td>
                            <td><?= sanitize($log['actor_username'] ?: ($log['actor_role'] ?: 'System')) ?></td>
                            <td><?= sanitize($log['description'] ?: '-') ?></td>
                            <td style="white-space: nowrap;"><?= date('d M Y, h:i A', strtotime($log['created_at'])) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<!-- FILE ACTIVITY & SECURITY OVERVIEW -->
<div class="card-grid">
    <div class="card">
        <h3 class="card-title">📁 File Activity Summary</h3>
        <ul style="list-style: none; margin-top: 10px;">
            <li style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span>Total Files Stored:</span> <strong><?= $stats['files']['total'] ?></strong>
            </li>
            <li style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span>AES-256-GCM Encrypted:</span> <strong><?= $stats['files']['encrypted'] ?></strong>
            </li>
            <li style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span>Active Shares:</span> <strong><?= $stats['shares']['pending'] ?></strong>
            </li>
            <li style="padding: 8px 0; display: flex; justify-content: space-between;">
                <span>Expired/Failed Shares:</span> <strong><?= $stats['shares']['failed'] ?></strong>
            </li>
        </ul>
        <a href="/owner/files.php" class="btn btn-secondary btn-sm" style="margin-top: 15px; width: 100%;">Inspect File Metrics</a>
    </div>

    <div class="card">
        <h3 class="card-title">🛡️ Security Overview</h3>
        <ul style="list-style: none; margin-top: 10px;">
            <li style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span>Failed Logins:</span> <strong style="color: var(--danger);"><?= $stats['security']['failed_logins'] ?></strong>
            </li>
            <li style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span>Failed Password Resets:</span> <strong style="color: var(--danger);"><?= $stats['security']['failed_resets'] ?></strong>
            </li>
            <li style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                <span>Suspended Users:</span> <strong style="color: var(--warning);"><?= $stats['users']['suspended'] ?></strong>
            </li>
            <li style="padding: 8px 0; display: flex; justify-content: space-between;">
                <span>Security Events Logged:</span> <strong><?= $stats['security']['suspicious_events'] ?></strong>
            </li>
        </ul>
        <a href="/owner/security.php" class="btn btn-secondary btn-sm" style="margin-top: 15px; width: 100%;">Inspect Security Logs</a>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
