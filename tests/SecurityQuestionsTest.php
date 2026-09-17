<?php
use Database\Database;
use Security\SecurityQuestions;

$db = Database::getInstance();

// 1. Check 500 active security questions in DB
$stmtCount = $db->query("SELECT COUNT(*) FROM security_questions WHERE active = 1");
$cnt = (int)$stmtCount->fetchColumn();
assertTest($cnt === 500, "Security Questions: Database contains EXACTLY 500 active questions");

// 2. Random selection of 5 distinct questions
$five = SecurityQuestions::getRandomFiveQuestions();
assertTest(count($five) === 5, "Security Questions: Returns exactly 5 questions");

$ids = array_column($five, 'id');
assertTest(count(array_unique($ids)) === 5, "Security Questions: Selection produces 5 DISTINCT question IDs");

// 3. User permanent assigned questions
$stmtUser = $db->query("SELECT id FROM users WHERE username = 'alice'");
$alice = $stmtUser->fetch();
$aliceId = (int)$alice['id'];

$assigned1 = SecurityQuestions::getUserQuestionsForReset($aliceId);
$assigned2 = SecurityQuestions::getUserQuestionsForReset($aliceId);

assertTest(count($assigned1) === 5, "Security Questions: User has 5 assigned questions");

$ids1 = array_column($assigned1, 'id');
$ids2 = array_column($assigned2, 'id');

sort($ids1);
sort($ids2);
assertTest($ids1 === $ids2, "Security Questions: Assigned 5 questions remain PERMANENT and identical across calls");
