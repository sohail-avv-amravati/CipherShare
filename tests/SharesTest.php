<?php
use Auth\AuthManager;
use Shares\ShareManager;
use Files\FileManager;
use Database\Database;

$db = Database::getInstance();

$stmtAlice = $db->query("SELECT id FROM users WHERE username = 'alice'");
$aliceId = (int)$stmtAlice->fetchColumn();

$stmtBob = $db->query("SELECT id FROM users WHERE username = 'bob'");
$bobId = (int)$stmtBob->fetchColumn();

$stmtFile = $db->prepare("SELECT id FROM files WHERE user_id = :id LIMIT 1");
$stmtFile->execute([':id' => $aliceId]);
$fileId = (int)$stmtFile->fetchColumn();

// Test 1: Alice creates share for Bob (30 min duration)
$err = null;
$shareId1 = ShareManager::createShare($aliceId, $fileId, 'bob', '30m', $err);
assertTest($shareId1 !== null, "File Sharing: Alice creates share link for recipient 'bob'");

// Test 2: Bob accesses share before expiration -> PENDING -> SUCCESS
AuthManager::login('bob', 'BobPass123!');
$accessData = ShareManager::accessSharedFile($bobId, $shareId1, $err);
assertTest($accessData !== null && $accessData['share']['status'] === 'SUCCESS', "File Sharing: Bob accesses valid share before expiration (PENDING -> SUCCESS)");
AuthManager::logout();

// Test 3: Share Expiration Test (Short expiration)
// Create a share expiring in 1 second
$shareId2 = bin2hex(random_bytes(16));
$expiresAt = date('Y-m-d H:i:s', time() - 5); // 5 seconds in the PAST (server clock expired)

$stmtExpShare = $db->prepare("
    INSERT INTO shares (share_id, sender_id, recipient_id, file_id, status, created_at, expires_at)
    VALUES (:share_id, :sender_id, :recipient_id, :file_id, 'PENDING', CURRENT_TIMESTAMP, :expires_at)
");
$stmtExpShare->execute([
    ':share_id' => $shareId2,
    ':sender_id' => $aliceId,
    ':recipient_id' => $bobId,
    ':file_id' => $fileId,
    ':expires_at' => $expiresAt
]);

// Bob attempts to access expired share
AuthManager::login('bob', 'BobPass123!');
$expiredAccess = ShareManager::accessSharedFile($bobId, $shareId2, $err);
assertTest($expiredAccess === null, "File Sharing: Denies access to expired share");
assertTest($err === "Recipient did not access the file before the expiration time.", "File Sharing: Displays exact failure message: 'Recipient did not access the file before the expiration time.'");

// Verify share status updated to FAILED in database
$stmtCheck = $db->prepare("SELECT status, failure_reason FROM shares WHERE share_id = :sid");
$stmtCheck->execute([':sid' => $shareId2]);
$rowCheck = $stmtCheck->fetch();
assertTest($rowCheck['status'] === 'FAILED', "File Sharing: Expired share status updated to FAILED");

// Test 4: Verify original file remains intact for Alice
AuthManager::logout();
AuthManager::login('alice', 'NewAlicePass123!');
$originalFileStillExists = FileManager::getUserFile($aliceId, $fileId);
assertTest($originalFileStillExists !== null, "File Sharing: Original file remains intact and accessible to sender Alice after share expiration");
AuthManager::logout();
