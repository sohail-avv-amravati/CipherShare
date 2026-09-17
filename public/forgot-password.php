<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Security\CSRF;

start_secure_session();

$error = null;
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF token validation failed. Please try again.";
    } else {
        $username = trim($_POST['username'] ?? '');
        $resetData = AuthManager::initiatePasswordReset($username, $error);
        if ($resetData) {
            redirect('/reset-password.php?token=' . urlencode($resetData['token']));
        }
    }
}

$pageTitle = "Forgot Password";
include BASE_DIR . '/templates/header.php';
?>

<div class="card form-card">
    <h2 class="card-title" style="font-size: 1.6rem; text-align: center; margin-bottom: 20px;">Forgot Password</h2>
    <p style="color: var(--text-muted); text-align: center; margin-bottom: 24px;">
        Enter your username to begin security verification.
    </p>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/forgot-password.php" method="POST">
        <?= CSRF::getFormField() ?>

        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" class="form-control" value="<?= sanitize($username) ?>" required autocomplete="username">
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 10px;">Continue to Verification</button>
    </form>

    <div style="text-align: center; margin-top: 20px;">
        <a href="/login.php">Back to Login</a>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
