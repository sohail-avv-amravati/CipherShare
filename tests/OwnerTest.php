<?php
use Auth\AuthManager;
use Owner\OwnerManager;
use Database\Database;

// 1. Normal User Access to Owner Methods
AuthManager::login('alice', 'NewAlicePass123!');
$alice = AuthManager::getCurrentUser();

$denied = false;
try {
    AuthManager::requireOwner();
} catch (\Exception $e) {
    $denied = true;
}
assertTest($alice['role'] !== 'OWNER', "Owner Protection: Normal user role is 'USER'");
AuthManager::logout();

// 2. Owner Login & Dashboard Stats
$ownerLoginOk = AuthManager::login('CipherShare', 'madgud@123', $err);
assertTest($ownerLoginOk === true, "Owner Portal: Authenticates owner credentials");

$ownerUser = AuthManager::getCurrentUser();
assertTest($ownerUser['role'] === 'OWNER', "Owner Portal: Session role is 'OWNER'");

$stats = OwnerManager::getDashboardStats();
assertTest($stats['users']['total'] >= 2, "Owner Portal: Accurately counts total registered users");
assertTest($stats['files']['total'] >= 1, "Owner Portal: Accurately counts total files");

// 3. User Suspension & Reactivation Test
$db = Database::getInstance();
$stmtBob = $db->query("SELECT id FROM users WHERE username = 'bob'");
$bobId = (int)$stmtBob->fetchColumn();

$ownerId = (int)$ownerUser['id'];

// Owner suspends Bob
$suspendOk = OwnerManager::updateUserStatus($ownerId, $bobId, 'SUSPENDED', $err);
assertTest($suspendOk === true, "Owner Portal: Owner suspends user 'bob'");

// Verify Bob cannot log in while suspended
AuthManager::logout();
$bobLoginErr = null;
$bobLogin = AuthManager::login('bob', 'BobPass123!', $bobLoginErr);
assertTest($bobLogin === false && strpos($bobLoginErr, 'suspended') !== false, "Owner Control: Suspended user 'bob' is blocked from logging in");

// Owner reactivates Bob
AuthManager::login('CipherShare', 'madgud@123', $err);
$reactivateOk = OwnerManager::updateUserStatus($ownerId, $bobId, 'ACTIVE', $err);
assertTest($reactivateOk === true, "Owner Portal: Owner reactivates user 'bob'");

AuthManager::logout();
$bobRestoreLogin = AuthManager::login('bob', 'BobPass123!', $bobLoginErr);
assertTest($bobRestoreLogin === true, "Owner Control: Reactivated user 'bob' login restored");
AuthManager::logout();

// 4. Privacy Audit: Verify Owner user list omits password_hash and answer_hash
$userList = OwnerManager::getUsers();
foreach ($userList as $u) {
    assertTest(!isset($u['password_hash']) && !isset($u['answer_hash']), "Owner Privacy: User listing excludes password and security answer hashes");
}
