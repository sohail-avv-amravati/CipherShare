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
        $error = "CSRF verification failed.";
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        $user = AuthManager::login($username, $password, $error);
        if ($user) {
            if ($user['role'] === 'owner') {
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

<div style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 70vh;">
    <div class="card form-card" style="width: 100%; text-align: center;">
        <div style="font-size: 3rem; margin-bottom: 10px;">???</div>
        <h2 style="margin-bottom: 5px;">Welcome Back</h2>
        <p style="color: var(--text-muted); margin-bottom: 25px;">Sign in to continue to CipherShare.</p>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= sanitize($error) ?></div>
        <?php endif; ?>

        <form action="/login.php" method="POST" style="text-align: left;">
            <?= CSRF::getFormField() ?>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 10px;">Sign In</button>
        </form>
        
        <div style="margin-top: 20px; font-size: 0.9rem;">
            <a href="#" style="color: var(--text-muted);">Forgot Password?</a> | 
            <a href="/register.php">Create Account</a>
        </div>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
