<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Owner\OwnerManager;

$owner = AuthManager::requireOwner();
$securityEvents = OwnerManager::getSecurityEvents(100);
$stats = OwnerManager::getDashboardStats()['security'];

$pageTitle = "Security Center";
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">🛡️ Security Telemetry & Indicators</h1>
        <p class="section-subtitle">Objective security metrics showing authentication failures, rate-limiting triggers, and authorization violations.</p>
    </div>
</div>

<div class="card-grid">
    <div class="card">
        <div class="card-title">Failed Logins</div>
        <div class="stat-number" style="color: var(--danger);"><?= $stats['failed_logins'] ?></div>
        <p class="stat-desc">Authentication failures</p>
    </div>

    <div class="card">
        <div class="card-title">Failed Password Resets</div>
        <div class="stat-number" style="color: var(--warning);"><?= $stats['failed_resets'] ?></div>
        <p class="stat-desc">Incorrect security question attempts</p>
    </div>

    <div class="card">
        <div class="card-title">Security Event Logs</div>
        <div class="stat-number"><?= $stats['suspicious_events'] ?></div>
        <p class="stat-desc">Total telemetry records</p>
    </div>
</div>

<div class="card">
    <h3 class="card-title" style="margin-bottom: 20px;">Security Event Log</h3>

    <?php if (empty($securityEvents)): ?>
        <div class="empty-state">
            <div class="empty-state-icon">🛡️</div>
            <div class="empty-state-text">No security warning events recorded.</div>
            <div class="empty-state-sub">Security anomalies will be displayed here as they are detected.</div>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Event ID</th>
                        <th>User</th>
                        <th>Event Type</th>
                        <th>Details</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($securityEvents as $se): ?>
                        <tr>
                            <td>#<?= $se['id'] ?></td>
                            <td><strong><?= $se['username'] ? sanitize($se['username']) : 'Unauthenticated / Guest' ?></strong></td>
                            <td>
                                <span class="badge badge-security"><?= sanitize($se['event_type']) ?></span>
                            </td>
                            <td style="font-size: 0.9rem;"><?= sanitize($se['details'] ?? '-') ?></td>
                            <td style="font-size: 0.85rem; color: var(--text-muted); white-space: nowrap;"><?= date('d M Y, h:i A', strtotime($se['created_at'])) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
