<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Security\CSRF;

if (AuthManager::getCurrentUser()) {
    redirect('/dashboard.php');
}

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed. Please try again.";
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        $user = AuthManager::login($username, $password, $error);
        if ($user) {
            if ($user['role'] === 'OWNER') {
                redirect('/owner/dashboard.php');
            } else {
                redirect('/dashboard.php');
            }
        }
    }
}

$pageTitle = "Login - CipherShare";
include BASE_DIR . '/templates/header.php';
?>

<div class="form-card">
    <div style="text-align: center; margin-bottom: 22px;">
        <div style="font-size: 2.2rem; margin-bottom: 6px;">🛡️</div>
        <h2 style="font-size: 1.5rem; font-weight: 800; color: var(--text-main); margin-bottom: 4px;">Welcome Back</h2>
        <p style="color: var(--text-muted); font-size: 0.88rem;">Sign in to continue to CipherShare</p>
    </div>
    
    <?php if ($error): ?>
        <div class="alert alert-danger">⚠️ <?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/login.php" method="POST">
        <?= CSRF::getFormField() ?>
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" class="form-control" placeholder="Enter your username" required autofocus autocomplete="username">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" name="password" id="password" class="form-control" placeholder="Enter your password" required autocomplete="current-password">
        </div>
        <button type="submit" class="btn btn-primary" style="margin-top: 6px;">Sign In &rarr;</button>
    </form>
    
    <div style="margin-top: 20px; text-align: center; font-size: 0.88rem; color: var(--text-muted); display: flex; justify-content: space-between; align-items: center;">
        <a href="/forgot-password.php" style="color: var(--text-muted);">Forgot Password?</a>
        <a href="/register.php" style="font-weight: 600;">Create Account</a>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
