<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Security\CSRF;

start_secure_session();

if (AuthManager::getCurrentUser()) {
    redirect('/dashboard.php');
}

$error = null;
$username = '';

// STEP 1: Collect username + password
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF validation failed. Please refresh and try again.";
    } else {
        $username        = trim($_POST['username']    ?? '');
        $password        = $_POST['password']         ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if (empty($username) || mb_strlen($username) < 3 || mb_strlen($username) > 30) {
            $error = "Username must be between 3 and 30 characters.";
        } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
            $error = "Username can only contain letters, numbers, underscores, and hyphens.";
        } else {
            $pwError = null;
            if (!AuthManager::validatePassword($password, $confirmPassword, $pwError)) {
                $error = $pwError;
            } else {
                $db = \Database\Database::getInstance();
                $stmt = $db->prepare("SELECT id FROM users WHERE LOWER(username) = LOWER(:u)");
                $stmt->execute([':u' => $username]);
                if ($stmt->fetch()) {
                    $error = "Username is already taken. Please choose another.";
                } else {
                    $_SESSION['reg_username'] = $username;
                    $_SESSION['reg_password'] = $password;
                    redirect('/register-questions.php');
                }
            }
        }
    }
}

$pageTitle = "Create Account";
include BASE_DIR . '/templates/header.php';
?>

<div class="form-card">
    <div style="text-align: center; margin-bottom: 24px;">
        <span class="badge badge-auth" style="margin-bottom: 10px;">Step 1 of 2</span>
        <h1 style="font-size: 1.6rem; font-weight: 800; color: var(--text-main); margin-bottom: 4px;">Create Account</h1>
        <p style="font-size: 0.88rem; color: var(--text-muted);">Join CipherShare to store & share encrypted files</p>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger">⚠️ <?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/register.php" method="POST" autocomplete="off">
        <?= CSRF::getFormField() ?>

        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" class="form-control" value="<?= sanitize($username) ?>" placeholder="e.g. alex_smith" required minlength="3" maxlength="30" autocomplete="off" autofocus>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" class="form-control" placeholder="At least 8 characters" required minlength="8" autocomplete="new-password">
        </div>

        <div class="form-group">
            <label for="confirm_password">Confirm Password</label>
            <input type="password" id="confirm_password" name="confirm_password" class="form-control" placeholder="Re-enter password" required minlength="8" autocomplete="new-password">
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 8px;">
            Continue &rarr;
        </button>
    </form>

    <div style="text-align: center; margin-top: 20px; font-size: 0.88rem; color: var(--text-muted);">
        Already have an account? <a href="/login.php" style="font-weight: 600;">Log in</a>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
