<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Owner\OwnerManager;
use Security\CSRF;
use Database\Database;

$owner = AuthManager::requireOwner();
$ownerId = (int)$owner['id'];
$error = null;

// Confirmation Step or Direct Action Post
$action = $_GET['action'] ?? $_POST['action'] ?? null;
$confirmUserId = (int)($_GET['user_id'] ?? $_POST['target_user_id'] ?? 0);
$confirmUser = null;

if ($confirmUserId > 0) {
    $db = Database::getInstance();
    $stmt = $db->prepare("SELECT id, username, status, role FROM users WHERE id = :id AND role = 'USER'");
    $stmt->execute([':id' => $confirmUserId]);
    $confirmUser = $stmt->fetch();
}

// Process Post Status Update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'execute_update_status') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        $targetUserId = (int)($_POST['target_user_id'] ?? 0);
        $newStatus = $_POST['new_status'] ?? '';
        if (OwnerManager::updateUserStatus($ownerId, $targetUserId, $newStatus, $error)) {
            set_flash_message('success', "User account status changed to {$newStatus}.");
            redirect('/owner/users.php');
        }
    }
}

$search = $_GET['search'] ?? null;
$statusFilter = $_GET['status'] ?? null;
$users = OwnerManager::getUsers($search, $statusFilter);

$pageTitle = "User Management";
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">👥 User Management</h1>
        <p class="section-subtitle">Search, inspect objective security indicators, and manage user accounts.</p>
    </div>
</div>

<?php if ($error): ?>
    <div class="alert alert-danger"><?= sanitize($error) ?></div>
<?php endif; ?>

<!-- CONFIRMATION WORKFLOW STEP -->
<?php if (in_array($action, ['confirm_suspend', 'confirm_reactivate', 'confirm_deactivate']) && $confirmUser): ?>
    <?php
        $targetStatus = 'SUSPENDED';
        $btnClass = 'btn-danger';
        $actionLabel = 'Suspend';
        if ($action === 'confirm_reactivate') {
            $targetStatus = 'ACTIVE';
            $btnClass = 'btn-success';
            $actionLabel = 'Reactivate';
        } elseif ($action === 'confirm_deactivate') {
            $targetStatus = 'DEACTIVATED';
            $btnClass = 'btn-warning';
            $actionLabel = 'Deactivate';
        }
    ?>
    <div class="confirm-box">
        <h3 class="confirm-title">⚠️ Confirm Administrative Action</h3>
        <p style="color: var(--text-muted); margin-bottom: 15px;">
            Are you sure you want to <strong><?= strtolower($actionLabel) ?></strong> the user account for <strong><?= sanitize($confirmUser['username']) ?></strong>?
        </p>
        <?php if ($targetStatus === 'SUSPENDED'): ?>
            <p style="font-size: 0.85rem; color: var(--danger); margin-bottom: 15px;">
                Suspended users are immediately blocked from logging in or performing any file actions.
            </p>
        <?php endif; ?>

        <form action="/owner/users.php" method="POST">
            <?= CSRF::getFormField() ?>
            <input type="hidden" name="action" value="execute_update_status">
            <input type="hidden" name="target_user_id" value="<?= $confirmUser['id'] ?>">
            <input type="hidden" name="new_status" value="<?= $targetStatus ?>">

            <div class="confirm-actions">
                <a href="/owner/users.php" class="btn btn-secondary">Cancel</a>
                <button type="submit" class="btn <?= $btnClass ?>">Yes, Confirm <?= $actionLabel ?></button>
            </div>
        </form>
    </div>
<?php endif; ?>

<!-- USER SEARCH & FILTER FORM -->
<div class="filter-card">
    <form action="/owner/users.php" method="GET" class="filter-form">
        <div class="filter-group" style="flex: 2;">
            <label for="search">Search Username</label>
            <input type="text" id="search" name="search" class="form-control" placeholder="Enter username..." value="<?= sanitize($search ?? '') ?>">
        </div>
        <div class="filter-group">
            <label for="status">Account Status</label>
            <select id="status" name="status" class="form-control">
                <option value="">-- All Statuses --</option>
                <option value="ACTIVE" <?= $statusFilter === 'ACTIVE' ? 'selected' : '' ?>>ACTIVE</option>
                <option value="SUSPENDED" <?= $statusFilter === 'SUSPENDED' ? 'selected' : '' ?>>SUSPENDED</option>
                <option value="DEACTIVATED" <?= $statusFilter === 'DEACTIVATED' ? 'selected' : '' ?>>DEACTIVATED</option>
            </select>
        </div>
        <div class="filter-group" style="flex: 0 0 auto;">
            <button type="submit" class="btn btn-primary btn-inline">Search Users</button>
        </div>
    </form>
</div>

<!-- USERS LISTING TABLE -->
<?php if (empty($users)): ?>
    <div class="empty-state">
        <div class="empty-state-icon">👥</div>
        <div class="empty-state-text">No users found.</div>
        <div class="empty-state-sub">Try refining your search query or status filter.</div>
    </div>
<?php else: ?>
    <div class="table-responsive">
        <table>
            <thead>
                <tr>
                    <th>User</th>
                    <th>Status</th>
                    <th>Registered</th>
                    <th>Last Login</th>
                    <th>Files</th>
                    <th>Shares</th>
                    <th>Objective Security Indicators</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $u): ?>
                    <tr>
                        <td>
                            <strong><?= sanitize($u['username']) ?></strong>
                            <div style="font-size: 0.75rem; color: var(--text-muted);">ID: #<?= $u['id'] ?></div>
                        </td>
                        <td>
                            <?php if ($u['status'] === 'ACTIVE'): ?>
                                <span class="badge badge-active">ACTIVE</span>
                            <?php elseif ($u['status'] === 'SUSPENDED'): ?>
                                <span class="badge badge-suspended">SUSPENDED</span>
                            <?php else: ?>
                                <span class="badge badge-deactivated">DEACTIVATED</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-size: 0.85rem; color: var(--text-muted); white-space: nowrap;">
                            <?= date('d M Y', strtotime($u['created_at'])) ?>
                        </td>
                        <td style="font-size: 0.85rem; color: var(--text-muted); white-space: nowrap;">
                            <?= $u['last_login_at'] ? date('d M Y, h:i A', strtotime($u['last_login_at'])) : 'Never' ?>
                        </td>
                        <td><?= $u['file_count'] ?></td>
                        <td><?= $u['shares_sent_count'] ?></td>
                        <td>
                            <?php 
                                $hasIndicators = false;
                                if (($u['failed_logins_1h'] ?? 0) > 0) {
                                    $hasIndicators = true;
                                    echo '<span class="indicator-badge indicator-warning">' . (int)$u['failed_logins_1h'] . ' failed logins (1h)</span> ';
                                }
                                if (($u['failed_resets_count'] ?? 0) > 0) {
                                    $hasIndicators = true;
                                    echo '<span class="indicator-badge indicator-danger">' . (int)$u['failed_resets_count'] . ' failed reset attempts</span> ';
                                }
                                if (($u['security_events_count'] ?? 0) > 0) {
                                    $hasIndicators = true;
                                    echo '<span class="indicator-badge indicator-warning">' . (int)$u['security_events_count'] . ' security logs</span> ';
                                }
                                if (!$hasIndicators) {
                                    echo '<span style="font-size: 0.85rem; color: var(--text-muted);">Normal activity</span>';
                                }
                            ?>
                        </td>
                        <td style="white-space: nowrap;">
                            <a href="/owner/user-activity.php?user_id=<?= $u['id'] ?>" class="btn btn-primary btn-sm">View Activity</a>
                            <?php if ($u['status'] === 'ACTIVE'): ?>
                                <a href="/owner/users.php?action=confirm_suspend&user_id=<?= $u['id'] ?>" class="btn btn-danger btn-sm">Suspend</a>
                                <a href="/owner/users.php?action=confirm_deactivate&user_id=<?= $u['id'] ?>" class="btn btn-secondary btn-sm">Deactivate</a>
                            <?php else: ?>
                                <a href="/owner/users.php?action=confirm_reactivate&user_id=<?= $u['id'] ?>" class="btn btn-success btn-sm">Reactivate</a>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>

<?php include BASE_DIR . '/templates/footer.php'; ?>
