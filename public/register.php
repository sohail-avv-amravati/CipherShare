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
        $error = "CSRF token validation failed. Please refresh and try again.";
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
<style>
.reg-wrapper{display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 130px);padding:32px 16px;}
.reg-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:14px;padding:44px 40px 36px;width:100%;max-width:460px;box-shadow:0 8px 40px rgba(0,0,0,0.45);}
.reg-logo{text-align:center;margin-bottom:6px;font-size:2rem;}
.reg-title{text-align:center;font-size:1.5rem;font-weight:700;color:var(--text-main);margin-bottom:4px;}
.reg-subtitle{text-align:center;font-size:0.875rem;color:var(--text-muted);margin-bottom:32px;}
.reg-steps{display:flex;align-items:flex-start;margin-bottom:32px;}
.reg-step{display:flex;flex-direction:column;align-items:center;flex:1;}
.reg-step-circle{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.85rem;font-weight:700;border:2px solid var(--border-color);background:var(--bg-main);color:var(--text-muted);z-index:1;}
.reg-step.active .reg-step-circle{background:var(--primary);border-color:var(--primary);color:#fff;box-shadow:0 0 0 4px rgba(14,165,233,0.18);}
.reg-step.done .reg-step-circle{background:var(--success);border-color:var(--success);color:#fff;}
.reg-step-label{font-size:0.72rem;color:var(--text-muted);margin-top:6px;}
.reg-step.active .reg-step-label{color:var(--primary);font-weight:600;}
.reg-connector{flex:1;height:2px;background:var(--border-color);margin-top:18px;}
.reg-field{margin-bottom:20px;}
.reg-field label{display:block;font-size:0.8rem;font-weight:600;color:var(--text-muted);margin-bottom:7px;letter-spacing:0.04em;text-transform:uppercase;}
.reg-field input{width:100%;padding:11px 14px;background:var(--bg-main);border:1.5px solid var(--border-color);border-radius:8px;color:var(--text-main);font-size:0.97rem;outline:none;}
.reg-field input:focus{border-color:var(--primary);}
.reg-field .hint{font-size:0.78rem;color:var(--text-muted);margin-top:5px;}
.reg-btn{width:100%;padding:13px;background:var(--primary);border:none;border-radius:8px;color:#fff;font-size:1rem;font-weight:700;cursor:pointer;margin-top:8px;letter-spacing:0.02em;}
.reg-btn:hover{background:var(--primary-hover);}
.reg-error{background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.4);border-radius:8px;padding:11px 14px;color:#F87171;font-size:0.9rem;margin-bottom:22px;}
.reg-login-link{text-align:center;margin-top:22px;font-size:0.875rem;color:var(--text-muted);}
</style>
<div class="reg-wrapper">
  <div class="reg-card">
    <div class="reg-logo">🔐</div>
    <h1 class="reg-title">Create Account</h1>
    <p class="reg-subtitle">Join CipherShare — secure file sharing</p>
    <div class="reg-steps">
      <div class="reg-step active">
        <div class="reg-step-circle">1</div>
        <div class="reg-step-label">Account</div>
      </div>
      <div class="reg-connector"></div>
      <div class="reg-step">
        <div class="reg-step-circle">2</div>
        <div class="reg-step-label">Security</div>
      </div>
    </div>
    <?php if ($error): ?>
    <div class="reg-error">⚠️ <?= sanitize($error) ?></div>
    <?php endif; ?>
    <form action="/register.php" method="POST" autocomplete="off">
      <?= CSRF::getFormField() ?>
      <div class="reg-field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" value="<?= sanitize($username) ?>" placeholder="e.g. john_doe" required minlength="3" maxlength="30" autocomplete="off">
        <div class="hint">3–30 chars — letters, numbers, _ and - only.</div>
      </div>
      <div class="reg-field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Min 8 chars with letters + numbers/symbols" required minlength="8" autocomplete="new-password">
        <div class="hint">At least 8 characters — mix of letters and numbers or symbols.</div>
      </div>
      <div class="reg-field">
        <label for="confirm_password">Confirm Password</label>
        <input type="password" id="confirm_password" name="confirm_password" placeholder="Re-enter your password" required minlength="8" autocomplete="new-password">
      </div>
      <button type="submit" class="reg-btn">Continue &rarr;</button>
    </form>
    <div class="reg-login-link">Already have an account? <a href="/login.php">Log in</a></div>
  </div>
</div>
<?php include BASE_DIR . '/templates/footer.php'; ?>
