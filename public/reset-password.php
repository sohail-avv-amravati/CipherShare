<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Security\SecurityQuestions;
use Security\CSRF;
use Database\Database;

start_secure_session();

$token = $_GET['token'] ?? $_POST['token'] ?? '';
if (empty($token)) {
    set_flash_message('danger', 'Invalid password reset request.');
    redirect('/forgot-password.php');
}

$db = Database::getInstance();
$stmt = $db->prepare("SELECT prs.*, u.username FROM password_reset_sessions prs JOIN users u ON prs.user_id = u.id WHERE prs.token = :token AND prs.used = 0");
$stmt->execute([':token' => $token]);
$session = $stmt->fetch();

if (!$session || strtotime($session['expires_at']) < time()) {
    set_flash_message('danger', 'Password reset session is invalid or expired.');
    redirect('/forgot-password.php');
}

$error = null;
$step = $session['is_verified'] ? 'NEW_PASSWORD' : 'VERIFY_QUESTIONS';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF token validation failed.";
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'verify_answers') {
            $submittedAnswers = $_POST['answers'] ?? []; // [ question_id => answer ]
            if (AuthManager::verifyPasswordResetAnswers($token, $submittedAnswers, $error)) {
                $step = 'NEW_PASSWORD';
            }
        } elseif ($action === 'set_new_password') {
            $newPassword = $_POST['new_password'] ?? '';
            $confirmPassword = $_POST['confirm_password'] ?? '';

            if (AuthManager::completePasswordReset($token, $newPassword, $confirmPassword, $error)) {
                set_flash_message('success', 'Your password has been successfully reset! Please login.');
                redirect('/login.php');
            }
        }
    }
}

// Fetch permanently assigned 5 security questions in randomized display order
$userId = (int)$session['user_id'];
$questions = SecurityQuestions::getUserQuestionsForReset($userId);

$pageTitle = "Reset Password";
include BASE_DIR . '/templates/header.php';
?>

<div class="card form-card">
    <h2 class="card-title" style="font-size: 1.6rem; text-align: center; margin-bottom: 20px;">
        Account Recovery: <?= sanitize($session['username']) ?>
    </h2>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= sanitize($error) ?></div>
    <?php endif; ?>

    <?php if ($step === 'VERIFY_QUESTIONS'): ?>
        <p style="color: var(--text-muted); font-size: 0.95rem; margin-bottom: 20px; text-align: center;">
            Answer ALL FIVE of your permanently assigned security questions to verify your identity.
        </p>

        <form action="/reset-password.php" method="POST">
            <?= CSRF::getFormField() ?>
            <input type="hidden" name="token" value="<?= sanitize($token) ?>">
            <input type="hidden" name="action" value="verify_answers">

            <?php foreach ($questions as $idx => $q): ?>
                <div class="form-group" style="background-color: #0F172A; padding: 15px; border-radius: var(--radius); border: 1px solid var(--border-color);">
                    <label style="color: var(--text-main); font-weight: 600;">
                        <?= sanitize($q['question_text']) ?>
                    </label>
                    <input type="text" name="answers[<?= $q['id'] ?>]" class="form-control" required style="margin-top: 8px;" placeholder="Your answer" autocomplete="off">
                </div>
            <?php endforeach; ?>

            <button type="submit" class="btn btn-primary" style="margin-top: 10px;">Verify All 5 Answers</button>
        </form>
    <?php else: ?>
        <div class="alert alert-success">
            ✓ Security questions verified successfully! Enter your new password below.
        </div>

        <form action="/reset-password.php" method="POST">
            <?= CSRF::getFormField() ?>
            <input type="hidden" name="token" value="<?= sanitize($token) ?>">
            <input type="hidden" name="action" value="set_new_password">

            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password" class="form-control" required autocomplete="new-password">
                <small style="color: var(--text-muted);">At least 8 characters with letters and numbers/symbols.</small>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm New Password</label>
                <input type="password" id="confirm_password" name="confirm_password" class="form-control" required autocomplete="new-password">
            </div>

            <button type="submit" class="btn btn-primary" style="margin-top: 10px;">Save New Password</button>
        </form>
    <?php endif; ?>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
