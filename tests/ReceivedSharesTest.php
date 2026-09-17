<?php
use Auth\AuthManager;
use Shares\ShareManager;
use Files\FileManager;
use Database\Database;

// Login as Alice to send a file to Bob
AuthManager::login('alice', 'NewAlicePass123!');
$alice = AuthManager::getCurrentUser();
$aliceId = (int)$alice['id'];

// Upload file for Alice
$tmpPath = STORAGE_TEMP . '/share_test_doc.pdf';
file_put_contents($tmpPath, "%PDF-1.4 CipherShare Received Share Test Document");

$uploaded = FileManager::uploadFile($aliceId, [
    'name' => 'received_test_document.pdf',
    'tmp_name' => $tmpPath,
    'error' => UPLOAD_ERR_OK,
    'size' => filesize($tmpPath)
]);

assertTest($uploaded !== null, "Received Shares Test: Alice uploaded test file");
$fileId = (int)$uploaded['id'];

// Create pending share for Bob
$shareId = ShareManager::createShare($aliceId, $fileId, 'bob', '1h');
assertTest($shareId !== null, "Received Shares Test: Alice created pending share for Bob");

// Switch session to Bob
AuthManager::logout();
AuthManager::login('bob', 'BobPass123!');
$bob = AuthManager::getCurrentUser();
$bobId = (int)$bob['id'];

// Fetch Received Shares for Bob
$receivedShares = ShareManager::getReceivedShares($bobId);
assertTest(count($receivedShares) >= 1, "Received Shares Test: Real received shares are displayed for Bob");

$targetShare = null;
foreach ($receivedShares as $rs) {
    if ($rs['share_id'] === $shareId) {
        $targetShare = $rs;
        break;
    }
}

assertTest($targetShare !== null, "Received Shares Test: Share record present in Bob's received list");
assertTest($targetShare['sender_username'] === 'alice', "Received Shares Test: Sender name 'alice' is shown correctly");
assertTest($targetShare['original_name'] === 'received_test_document.pdf', "Received Shares Test: File name is shown correctly");
assertTest(!empty($targetShare['created_at']), "Received Shares Test: Created time is recorded");
assertTest(!empty($targetShare['expires_at']), "Received Shares Test: Expiration time is recorded");
assertTest($targetShare['status'] === 'PENDING', "Received Shares Test: Status is PENDING initially");

// Access pending share before expiration
$accessErr = null;
$accessData = ShareManager::accessSharedFile($bobId, $shareId, $accessErr);
assertTest($accessData !== null && file_exists($accessData['file_path']), "Received Shares Test: Pending shares can be opened before expiration");

// Verify status updated to SUCCESS and accessed_at recorded
$updatedShares = ShareManager::getReceivedShares($bobId);
$updatedTarget = null;
foreach ($updatedShares as $us) {
    if ($us['share_id'] === $shareId) {
        $updatedTarget = $us;
        break;
    }
}
assertTest($updatedTarget['status'] === 'SUCCESS', "Received Shares Test: Status updated to SUCCESS after access");
assertTest(!empty($updatedTarget['accessed_at']), "Received Shares Test: Successful share records access timestamp");

// Test expired share access prevention
$db = Database::getInstance();
$expiredShareId = bin2hex(random_bytes(16));
$pastExpiry = date('Y-m-d H:i:s', time() - 3600);

$stmtInsExp = $db->prepare("
    INSERT INTO shares (share_id, sender_id, recipient_id, file_id, status, created_at, expires_at)
    VALUES (:sid, :sender, :rec, :fid, 'PENDING', :past, :past)
");
$stmtInsExp->execute([
    ':sid' => $expiredShareId,
    ':sender' => $aliceId,
    ':rec' => $bobId,
    ':fid' => $fileId,
    ':past' => $pastExpiry
]);

$expErr = null;
$expAccess = ShareManager::accessSharedFile($bobId, $expiredShareId, $expErr);
assertTest($expAccess === null && strpos($expErr, 'expiration time') !== false, "Received Shares Test: Expired shares CANNOT be opened by recipient");

// Verify expired share status updated to FAILED in DB
$expCheckShares = ShareManager::getReceivedShares($bobId);
$expTarget = null;
foreach ($expCheckShares as $ecs) {
    if ($ecs['share_id'] === $expiredShareId) {
        $expTarget = $ecs;
        break;
    }
}
assertTest($expTarget['status'] === 'FAILED', "Received Shares Test: Expired share status transitions to FAILED/EXPIRED");
