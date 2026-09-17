<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Security\CSRF;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if (AuthManager::changePassword($userId, $currentPassword, $newPassword, $confirmPassword, $error)) {
            set_flash_message('success', 'Your password has been changed successfully.');
            redirect('/account.php');
        }
    }
}

$pageTitle = "Account Settings";
include BASE_DIR . '/templates/header.php';
?>

<div style="max-width: 600px; margin: 0 auto;">
    <div class="section-header">
        <h1 class="section-title">Account Settings</h1>
    </div>

    <div class="card" style="margin-bottom: 25px;">
        <h3 class="card-title">User Profile</h3>
        <ul style="list-style: none; font-size: 0.95rem; color: var(--text-main);">
            <li style="padding: 8px 0; border-bottom: 1px dashed var(--border-color); display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted);">Username:</span> <strong><?= sanitize($user['username']) ?></strong>
            </li>
            <li style="padding: 8px 0; border-bottom: 1px dashed var(--border-color); display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted);">Account Role:</span> <strong><?= sanitize($user['role']) ?></strong>
            </li>
            <li style="padding: 8px 0; border-bottom: 1px dashed var(--border-color); display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted);">Account Status:</span> <span class="badge badge-active"><?= sanitize($user['status']) ?></span>
            </li>
            <li style="padding: 8px 0; display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted);">Registered At:</span> <span><?= sanitize($user['created_at']) ?></span>
            </li>
        </ul>
    </div>

    <div class="card">
        <h3 class="card-title">Change Password</h3>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?= sanitize($error) ?></div>
        <?php endif; ?>

        <form action="/account.php" method="POST">
            <?= CSRF::getFormField() ?>

            <div class="form-group">
                <label for="current_password">Current Password</label>
                <input type="password" id="current_password" name="current_password" class="form-control" required autocomplete="current-password">
            </div>

            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password" class="form-control" required autocomplete="new-password">
                <small style="color: var(--text-muted);">At least 8 characters with letters and numbers/symbols.</small>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm New Password</label>
                <input type="password" id="confirm_password" name="confirm_password" class="form-control" required autocomplete="new-password">
            </div>

            <button type="submit" class="btn btn-primary" style="margin-top: 10px; width: 100%;">Update Password</button>
        </form>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
