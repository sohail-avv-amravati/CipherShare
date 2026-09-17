<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Security\CSRF;

start_secure_session();

$currentUser = AuthManager::getCurrentUser();
if ($currentUser && $currentUser['role'] === 'OWNER') {
    redirect('/owner/dashboard.php');
}

$error = null;
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (AuthManager::login($username, $password, $error)) {
            $user = AuthManager::getCurrentUser();
            if ($user && $user['role'] === 'OWNER') {
                redirect('/owner/dashboard.php');
            } else {
                AuthManager::logout();
                $error = "Access denied. Only Owner accounts can access the Owner Portal.";
            }
        }
    }
}

$pageTitle = "Owner Portal Login";
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div class="card form-card" style="border-color: var(--warning);">
    <h2 class="card-title" style="font-size: 1.6rem; text-align: center; margin-bottom: 20px; color: var(--warning);">
        👑 CipherShare Owner Portal Login
    </h2>
    <p style="color: var(--text-muted); text-align: center; margin-bottom: 24px;">
        Administrative access strictly restricted to platform owners.
    </p>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/owner/login.php" method="POST">
        <?= CSRF::getFormField() ?>

        <div class="form-group">
            <label for="username">Owner Username</label>
            <input type="text" id="username" name="username" class="form-control" value="<?= sanitize($username) ?>" required autocomplete="username">
        </div>

        <div class="form-group">
            <label for="password">Owner Password</label>
            <input type="password" id="password" name="password" class="form-control" required autocomplete="current-password">
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 10px; background-color: var(--warning); color: #000;">
            Authenticate Owner
        </button>
    </form>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
