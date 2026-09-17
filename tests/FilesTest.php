<?php
use Auth\AuthManager;
use Files\FileManager;
use Database\Database;

// Login as Alice
AuthManager::login('alice', 'NewAlicePass123!');
$alice = AuthManager::getCurrentUser();
$aliceId = (int)$alice['id'];

// Create temporary file on disk for upload test
$tmpFilePath = STORAGE_TEMP . '/test_upload.txt';
file_put_contents($tmpFilePath, "Alice's Secret Project Specs");

$fileArray = [
    'name' => 'project_specs.txt',
    'type' => 'text/plain',
    'tmp_name' => $tmpFilePath,
    'error' => UPLOAD_ERR_OK,
    'size' => filesize($tmpFilePath)
];

// Note: move_uploaded_file won't work with synthetic mock file in CLI, so let's insert file record directly to emulate upload
$db = Database::getInstance();
$storedName = bin2hex(random_bytes(16)) . '.txt';
$targetUploadPath = STORAGE_UPLOADS . '/' . $storedName;
copy($tmpFilePath, $targetUploadPath);

$stmtIns = $db->prepare("INSERT INTO files (user_id, original_name, stored_name, mime_type, file_size, is_encrypted, created_at) VALUES (:u, 'project_specs.txt', :s, 'text/plain', :sz, 0, CURRENT_TIMESTAMP)");
$stmtIns->execute([':u' => $aliceId, ':s' => $storedName, ':sz' => filesize($tmpFilePath)]);
$fileId = (int)$db->lastInsertId();

assertTest($fileId > 0, "Files Engine: File record created in database");

// Test File Retrieval & IDOR protection
$aliceFile = FileManager::getUserFile($aliceId, $fileId);
assertTest($aliceFile !== null, "Files Engine: Alice can access her own file");

// Login as Bob
AuthManager::logout();
AuthManager::login('bob', 'BobPass123!');
$bob = AuthManager::getCurrentUser();
$bobId = (int)$bob['id'];

$bobAccess = FileManager::getUserFile($bobId, $fileId);
assertTest($bobAccess === null, "IDOR Protection: Bob CANNOT access Alice's private file directly");

// Test File AES-256-GCM Encryption
AuthManager::logout();
AuthManager::login('alice', 'NewAlicePass123!');

$encErr = null;
$encOk = FileManager::encryptUserFile($aliceId, $fileId, "AliceSecretKey#1", $encErr);
assertTest($encOk === true, "Files Engine: Successfully encrypts Alice's file with AES-256-GCM");

$encFile = FileManager::getUserFile($aliceId, $fileId);
assertTest((int)$encFile['is_encrypted'] === 1, "Files Engine: Database records is_encrypted = 1");

// Test File Decryption
$decData = FileManager::decryptUserFile($aliceId, $fileId, "AliceSecretKey#1", $encErr);
assertTest($decData !== null && $decData['content'] === "Alice's Secret Project Specs", "Files Engine: Successfully decrypts file content");
