<?php
use Auth\AuthManager;
use Security\SecurityQuestions;

// 1. Password Policy Test
$err = null;
assertTest(AuthManager::validatePassword('Short1!', 'Short1!', $err) === false, "Password Policy: Rejects password < 8 chars");
assertTest(AuthManager::validatePassword('ValidPass123!', 'ValidPass123!', $err) === true, "Password Policy: Accepts valid password with symbols");

// 2. User Registration Test
$qPool = SecurityQuestions::getRandomFiveQuestions();
$answers = [];
foreach ($qPool as $q) {
    $answers[$q['id']] = "TestAnswer_" . $q['id'];
}

$err = null;
$regOk = AuthManager::register('alice', 'SecurePass123!', 'SecurePass123!', $answers, $err);
assertTest($regOk === true, "Registration: Successfully registers user 'alice' with 5 security questions");

// Duplicate username test
$dupOk = AuthManager::register('alice', 'SecurePass123!', 'SecurePass123!', $answers, $err);
assertTest($dupOk === false && strpos($err, 'already taken') !== false, "Registration: Rejects duplicate username 'alice'");

// Register second user 'bob'
$qPool2 = SecurityQuestions::getRandomFiveQuestions();
$answers2 = [];
foreach ($qPool2 as $q) {
    $answers2[$q['id']] = "BobAnswer_" . $q['id'];
}
AuthManager::register('bob', 'BobPass123!', 'BobPass123!', $answers2, $err);

// 3. Login Test
$loginErr = null;
assertTest(AuthManager::login('alice', 'WrongPass!', $loginErr) === false, "Login: Rejects incorrect password");
assertTest(AuthManager::login('alice', 'SecurePass123!', $loginErr) === true, "Login: Authenticates 'alice' with valid credentials");
assertTest(AuthManager::getCurrentUser()['username'] === 'alice', "Login: Session sets current user to 'alice'");

AuthManager::logout();
assertTest(AuthManager::getCurrentUser() === null, "Logout: Destroys session cleanly");
