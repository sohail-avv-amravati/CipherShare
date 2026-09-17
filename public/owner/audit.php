<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Owner\OwnerManager;

$owner = AuthManager::requireOwner();

// Server-side Filtering Parameters
$category = $_GET['category'] ?? 'ALL';
$eventType = $_GET['event_type'] ?? '';
$username = $_GET['username'] ?? '';
$dateFrom = $_GET['date_from'] ?? '';
$dateTo = $_GET['date_to'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 15;

$filters = [
    'category' => $category,
    'event_type' => $eventType,
    'username' => $username,
    'date_from' => $dateFrom,
    'date_to' => $dateTo
];

$auditData = OwnerManager::getAuditLogsFiltered($filters, $page, $perPage);
$auditLogs = $auditData['items'];
$totalPages = $auditData['total_pages'];
$currentPage = $auditData['current_page'];
$totalItems = $auditData['total_items'];

// Build Pagination Query String helper
function build_pagination_url(int $p, array $f): string {
    $f['page'] = $p;
    return '/owner/audit.php?' . http_build_query($f);
}

$pageTitle = "Dynamic Audit Trail";
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">📋 Dynamic System Audit Trail</h1>
        <p class="section-subtitle">Real-time immutable audit records generated dynamically from actual system operations.</p>
    </div>
</div>

<!-- FILTERING FORM (Pure PHP GET Form, No JavaScript) -->
<div class="filter-card">
    <form action="/owner/audit.php" method="GET" class="filter-form">
        <div class="filter-group">
            <label for="category">Category</label>
            <select id="category" name="category" class="form-control">
                <option value="ALL" <?= $category === 'ALL' ? 'selected' : '' ?>>-- All Categories --</option>
                <option value="AUTH" <?= $category === 'AUTH' ? 'selected' : '' ?>>Authentication</option>
                <option value="FILE" <?= $category === 'FILE' ? 'selected' : '' ?>>Files</option>
                <option value="SHARE" <?= $category === 'SHARE' ? 'selected' : '' ?>>Sharing</option>
                <option value="OWNER" <?= $category === 'OWNER' ? 'selected' : '' ?>>Owner Actions</option>
                <option value="SECURITY" <?= $category === 'SECURITY' ? 'selected' : '' ?>>Security Events</option>
            </select>
        </div>

        <div class="filter-group">
            <label for="event_type">Event Type</label>
            <input type="text" id="event_type" name="event_type" class="form-control" placeholder="e.g. LOGIN, UPLOAD..." value="<?= sanitize($eventType) ?>">
        </div>

        <div class="filter-group">
            <label for="username">Username / Actor</label>
            <input type="text" id="username" name="username" class="form-control" placeholder="Filter by username..." value="<?= sanitize($username) ?>">
        </div>

        <div class="filter-group">
            <label for="date_from">From Date</label>
            <input type="date" id="date_from" name="date_from" class="form-control" value="<?= sanitize($dateFrom) ?>">
        </div>

        <div class="filter-group">
            <label for="date_to">To Date</label>
            <input type="date" id="date_to" name="date_to" class="form-control" value="<?= sanitize($dateTo) ?>">
        </div>

        <div class="filter-group" style="flex: 0 0 auto;">
            <button type="submit" class="btn btn-primary btn-inline">Apply Filters</button>
            <a href="/owner/audit.php" class="btn btn-secondary btn-inline" style="margin-left: 5px;">Reset</a>
        </div>
    </form>
</div>

<!-- AUDIT LOG TABLE / EMPTY STATE -->
<?php if (empty($auditLogs)): ?>
    <div class="empty-state">
        <div class="empty-state-icon">📋</div>
        <div class="empty-state-text">No activity recorded yet.</div>
        <div class="empty-state-sub">Audit entries will appear automatically as real user and system events occur.</div>
    </div>
<?php else: ?>
    <div style="margin-bottom: 10px; font-size: 0.85rem; color: var(--text-muted);">
        Showing <?= count($auditLogs) ?> of <?= $totalItems ?> total recorded events
    </div>

    <div class="table-responsive">
        <table>
            <thead>
                <tr>
                    <th>Log ID</th>
                    <th>Category</th>
                    <th>Event Type</th>
                    <th>Actor</th>
                    <th>Target / Related Object</th>
                    <th>Description</th>
                    <th>IP Address</th>
                    <th>Date / Time</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($auditLogs as $al): 
                    $cat = strtolower($al['event_category'] ?? 'general');
                    $actor = $al['actor_username'] ?: ($al['actor_role'] ? "Role: {$al['actor_role']}" : 'System/Guest');
                    $target = '-';
                    if ($al['target_username']) {
                        $target = 'User: ' . sanitize($al['target_username']);
                    } elseif ($al['target_file_name']) {
                        $target = 'File: ' . sanitize($al['target_file_name']);
                    } elseif ($al['target_share_id']) {
                        $target = 'Share ID #' . (int)$al['target_share_id'];
                    }
                ?>
                    <tr>
                        <td>#<?= $al['id'] ?></td>
                        <td><span class="badge badge-<?= $cat ?>"><?= sanitize($al['event_category']) ?></span></td>
                        <td><strong><?= sanitize($al['event_type']) ?></strong></td>
                        <td style="font-weight: 500;"><?php
                            if ($al['actor_user_id']) {
                                echo '<a href="/owner/user-activity.php?user_id=' . (int)$al['actor_user_id'] . '" style="font-weight:600;">' . sanitize($actor) . '</a>';
                            } else {
                                echo sanitize($actor);
                            }
                        ?></td>
                        <td style="font-size: 0.85rem; color: var(--text-muted);"><?= $target ?></td>
                        <td style="font-size: 0.9rem;"><?= sanitize($al['description'] ?: '-') ?></td>
                        <td style="font-size: 0.85rem; font-family: monospace; color: var(--text-muted);"><?= sanitize($al['ip_address'] ?? '127.0.0.1') ?></td>
                        <td style="font-size: 0.85rem; color: var(--text-muted); white-space: nowrap;"><?= date('d M Y, h:i A', strtotime($al['created_at'])) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- SERVER-SIDE PAGINATION LINKS (Pure HTML, No JavaScript) -->
    <?php if ($totalPages > 1): ?>
        <div class="pagination">
            <?php if ($currentPage > 1): ?>
                <a href="<?= build_pagination_url($currentPage - 1, $filters) ?>">&laquo; Previous</a>
            <?php else: ?>
                <span class="disabled">&laquo; Previous</span>
            <?php endif; ?>

            <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                <?php if ($p === $currentPage): ?>
                    <span class="active"><?= $p ?></span>
                <?php else: ?>
                    <a href="<?= build_pagination_url($p, $filters) ?>"><?= $p ?></a>
                <?php endif; ?>
            <?php endfor; ?>

            <?php if ($currentPage < $totalPages): ?>
                <a href="<?= build_pagination_url($currentPage + 1, $filters) ?>">Next &raquo;</a>
            <?php else: ?>
                <span class="disabled">Next &raquo;</span>
            <?php endif; ?>
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php include BASE_DIR . '/templates/footer.php'; ?>
