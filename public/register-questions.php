<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Security\SecurityQuestions;
use Security\CSRF;

start_secure_session();

if (AuthManager::getCurrentUser()) {
    redirect('/dashboard.php');
}

// Must have come through step 1
if (empty($_SESSION['reg_username']) || empty($_SESSION['reg_password'])) {
    redirect('/register.php');
}

$error  = null;
$totalQ = 5;

// Load the 5 assigned questions (persist in session so they don't shuffle on reload)
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

// Which question are we on? (0-indexed)
$currentIdx = count($answers); // 0..4

// ── POST: answer submitted for current question ───────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF token validation failed. Please refresh and try again.";
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
            // Store answer
            $_SESSION['reg_answers'][$qId] = $rawAnswer;
            $answers = $_SESSION['reg_answers'];
            $currentIdx = count($answers);

            // All 5 answered — register the account
            if ($currentIdx >= $totalQ) {
                $regError = null;
                $username = $_SESSION['reg_username'];
                $password = $_SESSION['reg_password'];
                $answerMap = $_SESSION['reg_answers'];

                // Clean up session
                unset($_SESSION['reg_username'], $_SESSION['reg_password'],
                      $_SESSION['reg_questions'], $_SESSION['reg_answers']);

                if (AuthManager::register($username, $password, $password, $answerMap, $regError)) {
                    set_flash_message('success', 'Account created! You can now log in.');
                    redirect('/login.php');
                } else {
                    set_flash_message('danger', 'Registration failed: ' . $regError);
                    redirect('/register.php');
                }
            }
        }
    }
}

// Guard: if somehow all answered but no POST, redirect to login
if ($currentIdx >= $totalQ) {
    redirect('/login.php');
}

$currentQ   = $questions[$currentIdx];
$doneCount  = $currentIdx;           // how many answered
$percent    = (int)(($doneCount / $totalQ) * 100);

$pageTitle = "Security Questions";
include BASE_DIR . '/templates/header.php';
?>
<style>
.reg-wrapper{display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 130px);padding:32px 16px;}
.reg-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:14px;padding:44px 40px 36px;width:100%;max-width:500px;box-shadow:0 8px 40px rgba(0,0,0,0.45);}
.reg-logo{text-align:center;margin-bottom:6px;font-size:2rem;}
.reg-title{text-align:center;font-size:1.5rem;font-weight:700;color:var(--text-main);margin-bottom:4px;}
.reg-subtitle{text-align:center;font-size:0.875rem;color:var(--text-muted);margin-bottom:28px;}

/* Stepper */
.reg-steps{display:flex;align-items:flex-start;margin-bottom:28px;}
.reg-step{display:flex;flex-direction:column;align-items:center;flex:1;}
.reg-step-circle{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.85rem;font-weight:700;border:2px solid var(--border-color);background:var(--bg-main);color:var(--text-muted);z-index:1;}
.reg-step.active .reg-step-circle{background:var(--primary);border-color:var(--primary);color:#fff;box-shadow:0 0 0 4px rgba(14,165,233,0.18);}
.reg-step.done .reg-step-circle{background:var(--success);border-color:var(--success);color:#fff;}
.reg-step-label{font-size:0.72rem;color:var(--text-muted);margin-top:6px;}
.reg-step.active .reg-step-label{color:var(--primary);font-weight:600;}
.reg-step.done .reg-step-label{color:var(--success);font-weight:600;}
.reg-connector{flex:1;height:2px;background:var(--border-color);margin-top:18px;}
.reg-connector.done{background:var(--success);}

/* Progress bar */
.prog-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;}
.prog-label{font-size:0.82rem;color:var(--text-muted);}
.prog-count{font-size:0.82rem;font-weight:700;color:var(--success);}
.prog-bar-bg{width:100%;height:7px;background:#1E293B;border-radius:99px;margin-bottom:28px;overflow:hidden;}
.prog-bar-fill{height:100%;background:linear-gradient(90deg,#059669,#10B981);border-radius:99px;transition:width 0.4s ease;}

/* Question card */
.q-number{font-size:0.75rem;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:var(--primary);margin-bottom:10px;}
.q-text{font-size:1.05rem;font-weight:600;color:var(--text-main);line-height:1.5;margin-bottom:22px;background:rgba(14,165,233,0.07);border-left:3px solid var(--primary);border-radius:0 6px 6px 0;padding:14px 16px;}

/* Input */
.reg-field{margin-bottom:20px;}
.reg-field label{display:block;font-size:0.8rem;font-weight:600;color:var(--text-muted);margin-bottom:7px;letter-spacing:0.04em;text-transform:uppercase;}
.reg-field input{width:100%;padding:12px 15px;background:var(--bg-main);border:1.5px solid var(--border-color);border-radius:8px;color:var(--text-main);font-size:0.97rem;outline:none;}
.reg-field input:focus{border-color:var(--success);box-shadow:0 0 0 3px rgba(16,185,129,0.15);}
.reg-field .hint{font-size:0.78rem;color:var(--text-muted);margin-top:5px;}

/* Buttons */
.reg-btn{width:100%;padding:13px;background:var(--success);border:none;border-radius:8px;color:#fff;font-size:1rem;font-weight:700;cursor:pointer;margin-top:4px;letter-spacing:0.02em;}
.reg-btn:hover{background:#059669;}
.reg-btn-final{background:var(--primary);}
.reg-btn-final:hover{background:var(--primary-hover);}
.reg-error{background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.4);border-radius:8px;padding:11px 14px;color:#F87171;font-size:0.9rem;margin-bottom:20px;}

/* Answered list */
.answered-list{margin-top:24px;border-top:1px solid var(--border-color);padding-top:18px;}
.answered-list-title{font-size:0.78rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px;}
.answered-item{display:flex;align-items:flex-start;gap:8px;margin-bottom:7px;font-size:0.83rem;color:var(--text-muted);}
.answered-item .tick{color:var(--success);font-size:0.95rem;margin-top:1px;flex-shrink:0;}
.answered-item .q-short{color:var(--text-main);opacity:0.75;}
</style>

<div class="reg-wrapper">
  <div class="reg-card">
    <div class="reg-logo">🛡️</div>
    <h1 class="reg-title">Security Questions</h1>
    <p class="reg-subtitle">These protect your account for password recovery</p>

    <!-- Step indicator -->
    <div class="reg-steps">
      <div class="reg-step done">
        <div class="reg-step-circle">✓</div>
        <div class="reg-step-label">Account</div>
      </div>
      <div class="reg-connector done"></div>
      <div class="reg-step active">
        <div class="reg-step-circle">2</div>
        <div class="reg-step-label">Security</div>
      </div>
    </div>

    <!-- Green progress bar -->
    <div class="prog-header">
      <span class="prog-label">Question progress</span>
      <span class="prog-count"><?= $doneCount ?> / <?= $totalQ ?> answered</span>
    </div>
    <div class="prog-bar-bg">
      <div class="prog-bar-fill" style="width: <?= $percent ?>%;"></div>
    </div>

    <!-- Current question -->
    <div class="q-number">Question <?= $doneCount + 1 ?> of <?= $totalQ ?></div>
    <div class="q-text"><?= sanitize($currentQ['question_text']) ?></div>

    <?php if ($error): ?>
    <div class="reg-error">⚠️ <?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/register-questions.php" method="POST" autocomplete="off">
      <?= CSRF::getFormField() ?>
      <input type="hidden" name="q_id" value="<?= (int)$currentQ['id'] ?>">

      <div class="reg-field">
        <label for="answer">Your Answer</label>
        <input type="text" id="answer" name="answer" placeholder="Type your answer here…" required autocomplete="off" autofocus>
        <div class="hint">Answers are case-insensitive. Remember them for future password recovery.</div>
      </div>

      <?php $isLast = ($doneCount + 1 >= $totalQ); ?>
      <button type="submit" class="reg-btn <?= $isLast ? 'reg-btn-final' : '' ?>">
        <?= $isLast ? '🎉 Create My Account' : 'Next &rarr;' ?>
      </button>
    </form>

    <!-- Show already-answered questions -->
    <?php if ($doneCount > 0): ?>
    <div class="answered-list">
      <div class="answered-list-title">✅ Answered so far</div>
      <?php foreach (array_slice($questions, 0, $doneCount) as $aq): ?>
      <div class="answered-item">
        <span class="tick">✓</span>
        <span class="q-short"><?= sanitize(mb_substr($aq['question_text'], 0, 60)) ?><?= mb_strlen($aq['question_text']) > 60 ? '…' : '' ?></span>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>

  </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
