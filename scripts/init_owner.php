<?php
require_once __DIR__ . '/../config/config.php';

use Database\Database;
use Security\AuditLogger;

echo "CipherShare Owner Initialization Tool\n";

$db = Database::getInstance();

$options = getopt("", ["username:", "password:"]);

$username = $options['username'] ?? 'CipherShare';
$password = $options['password'] ?? 'madgud@123';

// Check if owner already exists
$stmt = $db->prepare("SELECT id FROM users WHERE role = 'OWNER'");
$stmt->execute();
if ($stmt->fetch()) {
    echo "An OWNER account already exists in the database.\n";
    exit(0);
}

$hash = password_hash($password, PASSWORD_DEFAULT);

$stmtUser = $db->prepare("INSERT INTO users (username, password_hash, role, status, created_at) VALUES (:username, :hash, 'OWNER', 'ACTIVE', CURRENT_TIMESTAMP)");
$stmtUser->execute([
    ':username' => $username,
    ':hash' => $hash
]);

$ownerId = (int)$db->lastInsertId();
AuditLogger::log($ownerId, "OWNER_INITIALIZED", "Owner account '{$username}' created via local CLI");

echo "Owner account created successfully!\n";
echo "Username: {$username}\n";
echo "Role: OWNER\n";
