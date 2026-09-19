<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Security\SecurityQuestions;
use Security\CSRF;

start_secure_session();

if (AuthManager::getCurrentUser()) {
    redirect('/dashboard.php');
}

if (empty($_SESSION['reg_username']) || empty($_SESSION['reg_password'])) {
    redirect('/register.php');
}

$error  = null;
$totalQ = 5;

if (empty($_SESSION['reg_questions'])) {
    $qs = SecurityQuestions::getRandomFiveQuestions();
    if (count($qs) < 5) {
        $error = "Could not load security questions. Please try again.";
    } else {
        $_SESSION['reg_questions'] = $qs;
        $_SESSION['reg_answers']   = [];
    }
}

$questions = $_SESSION['reg_questions'] ?? [];
$answers   = $_SESSION['reg_answers']   ?? [];
$currentIdx = count($answers);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF validation failed. Please refresh and try again.";
    } else {
        $rawAnswer = trim($_POST['answer'] ?? '');
        $qId       = (int)($_POST['q_id'] ?? 0);

        if ($rawAnswer === '') {
            $error = "Please enter your answer before continuing.";
        } elseif (empty($questions[$currentIdx]) || (int)$questions[$currentIdx]['id'] !== $qId) {
            $error = "Question mismatch. Please start over.";
            unset($_SESSION['reg_questions'], $_SESSION['reg_answers'], $_SESSION['reg_username'], $_SESSION['reg_password']);
            redirect('/register.php');
        } else {
            $_SESSION['reg_answers'][$qId] = $rawAnswer;
            $answers = $_SESSION['reg_answers'];
            $currentIdx = count($answers);

            if ($currentIdx >= $totalQ) {
                $regError = null;
                $username = $_SESSION['reg_username'];
                $password = $_SESSION['reg_password'];
                $answerMap = $_SESSION['reg_answers'];

                unset($_SESSION['reg_username'], $_SESSION['reg_password'],
                      $_SESSION['reg_questions'], $_SESSION['reg_answers']);

                if (AuthManager::register($username, $password, $password, $answerMap, $regError)) {
                    set_flash_message('success', 'Account created successfully! You can now log in.');
                    redirect('/login.php');
                } else {
                    set_flash_message('danger', 'Registration failed: ' . $regError);
                    redirect('/register.php');
                }
            }
        }
    }
}

if ($currentIdx >= $totalQ) {
    redirect('/login.php');
}

$currentQ  = $questions[$currentIdx];
$doneCount = $currentIdx;
$percent   = (int)(($doneCount / $totalQ) * 100);

$pageTitle = "Security Questions";
include BASE_DIR . '/templates/header.php';
?>

<div class="form-card">
    <div style="text-align: center; margin-bottom: 20px;">
        <span class="badge badge-success" style="margin-bottom: 8px;">Step 2 of 2</span>
        <h1 style="font-size: 1.5rem; font-weight: 800; color: var(--text-main); margin-bottom: 4px;">Security Questions</h1>
        <p style="font-size: 0.85rem; color: var(--text-muted);">Set up security answers for password recovery</p>
    </div>

    <!-- Green progress bar -->
    <div style="margin-bottom: 18px;">
        <div style="display: flex; justify-content: space-between; font-size: 0.82rem; margin-bottom: 6px; color: var(--text-muted);">
            <span>Progress</span>
            <span style="font-weight: 700; color: var(--success);"><?= $doneCount ?> of <?= $totalQ ?> answered</span>
        </div>
        <div style="width: 100%; height: 6px; background: var(--bg-main); border-radius: 10px; overflow: hidden; border: 1px solid var(--border-color);">
            <div style="height: 100%; width: <?= $percent ?>%; background: var(--success); transition: width 0.3s ease;"></div>
        </div>
    </div>

    <!-- Current Question -->
    <div style="background: var(--bg-main); border-left: 3px solid var(--primary); padding: 12px 14px; border-radius: 0 8px 8px 0; margin-bottom: 18px;">
        <div style="font-size: 0.75rem; font-weight: 700; color: var(--primary); text-transform: uppercase; margin-bottom: 4px;">
            Question <?= $doneCount + 1 ?> of <?= $totalQ ?>
        </div>
        <div style="font-size: 0.95rem; font-weight: 600; color: var(--text-main);">
            <?= sanitize($currentQ['question_text']) ?>
        </div>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger">⚠️ <?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/register-questions.php" method="POST" autocomplete="off">
        <?= CSRF::getFormField() ?>
        <input type="hidden" name="q_id" value="<?= (int)$currentQ['id'] ?>">

        <div class="form-group">
            <label for="answer">Your Answer</label>
            <input type="text" id="answer" name="answer" class="form-control" placeholder="Type your answer..." required autocomplete="off" autofocus>
        </div>

        <?php $isLast = ($doneCount + 1 >= $totalQ); ?>
        <button type="submit" class="btn <?= $isLast ? 'btn-success' : 'btn-primary' ?>" style="margin-top: 6px;">
            <?= $isLast ? '🎉 Finish & Create Account' : 'Next Question &rarr;' ?>
        </button>
    </form>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
