<?php
use Auth\AuthManager;
use Database\Database;

$err = null;
$resetData = AuthManager::initiatePasswordReset('alice', $err);
assertTest($resetData !== null && !empty($resetData['token']), "Password Reset: Initiates reset session and generates token");

$token = $resetData['token'];
$aliceId = $resetData['user_id'];

// Get user's assigned question IDs
$db = Database::getInstance();
$stmtQ = $db->prepare("SELECT question_id FROM user_security_questions WHERE user_id = :id");
$stmtQ->execute([':id' => $aliceId]);
$qRows = $stmtQ->fetchAll(\PDO::FETCH_ASSOC);

// Test 1: Submit 4 correct answers + 1 WRONG answer
$wrongAnswers = [];
foreach ($qRows as $idx => $r) {
    $qId = $r['question_id'];
    if ($idx === 0) {
        $wrongAnswers[$qId] = "WRONG_ANSWER_VALUE";
    } else {
        $wrongAnswers[$qId] = "TestAnswer_" . $qId;
    }
}

$verifyErr = null;
$verifyWrong = AuthManager::verifyPasswordResetAnswers($token, $wrongAnswers, $verifyErr);
assertTest($verifyWrong === false && $verifyErr === "Security verification failed.", "Password Reset: Rejects reset if even 1 answer is wrong with generic message");

// Test 2: Submit ALL 5 CORRECT answers
$correctAnswers = [];
foreach ($qRows as $r) {
    $qId = $r['question_id'];
    $correctAnswers[$qId] = "TestAnswer_" . $qId;
}

$verifyRight = AuthManager::verifyPasswordResetAnswers($token, $correctAnswers, $verifyErr);
assertTest($verifyRight === true, "Password Reset: Accepts reset authorization when ALL 5 answers are correct");

// Test 3: Complete Password Reset
$completeErr = null;
$completeOk = AuthManager::completePasswordReset($token, 'NewAlicePass123!', 'NewAlicePass123!', $completeErr);
assertTest($completeOk === true, "Password Reset: Completes password update successfully");

// Test 4: Verify Alice can now log in with new password
$loginErr = null;
assertTest(AuthManager::login('alice', 'NewAlicePass123!', $loginErr) === true, "Password Reset: Alice can log in with new password");
AuthManager::logout();

// Test 5: Invalidate token after single use
$reuseErr = null;
$reuseOk = AuthManager::completePasswordReset($token, 'AnotherPass123!', 'AnotherPass123!', $reuseErr);
assertTest($reuseOk === false, "Password Reset: Prevents token reuse after completion");
