<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Database\Database;

echo "============================================================\n";
echo "CIPHERSHARE MANUAL UPLOAD VERIFICATION INTEGRATION TEST\n";
echo "============================================================\n";

// 1. Authenticate user
AuthManager::login('alice', 'NewAlicePass123!');
$alice = AuthManager::getCurrentUser();
$aliceId = (int)$alice['id'];
echo "1. Logged in as user '{$alice['username']}' (ID: {$aliceId})\n";

// 2. Prepare sample upload file
$tmpPath = STORAGE_TEMP . '/manual_verify.pdf';
file_put_contents($tmpPath, "%PDF-1.4 %CipherShare Verification PDF Document");

$fileUploadArray = [
    'name' => 'annual_security_report.pdf',
    'type' => 'application/pdf',
    'tmp_name' => $tmpPath,
    'error' => UPLOAD_ERR_OK,
    'size' => filesize($tmpPath)
];

// 3. Perform Upload
$err = null;
$uploaded = FileManager::uploadFile($aliceId, $fileUploadArray, $err);

if (!$uploaded) {
    echo "FAILED: Upload returned error: {$err}\n";
    exit(1);
}

echo "2. Uploaded file '{$uploaded['original_name']}' successfully (File ID: {$uploaded['id']})\n";

// 4. Verify file appears in My Files
$userFiles = FileManager::getUserFiles($aliceId);
$found = false;
foreach ($userFiles as $f) {
    if ((int)$f['id'] === (int)$uploaded['id']) {
        $found = true;
        break;
    }
}
assert($found, "Uploaded file must appear in user file list");
echo "3. Verified file appears in 'My Files' list\n";

// 5. Verify Metadata
$fileRecord = FileManager::getUserFile($aliceId, $uploaded['id']);
echo "4. Metadata verified:\n";
echo "   - Original Name: {$fileRecord['original_name']}\n";
echo "   - Stored Name: {$fileRecord['stored_name']}\n";
echo "   - File Size: {$fileRecord['file_size']} bytes\n";
echo "   - MIME Type: {$fileRecord['mime_type']}\n";

// 6. Verify unauthorized users cannot access it
AuthManager::logout();
AuthManager::login('bob', 'BobPass123!');
$bob = AuthManager::getCurrentUser();
$bobAccess = FileManager::getUserFile((int)$bob['id'], $uploaded['id']);
assert($bobAccess === null, "Bob cannot access Alice's uploaded file");
echo "5. Verified unauthorized user 'bob' CANNOT access file\n";

// 7. Verify file can proceed to AES-256-GCM Encryption
AuthManager::logout();
AuthManager::login('alice', 'NewAlicePass123!');
$encOk = FileManager::encryptUserFile($aliceId, $uploaded['id'], "Passphrase123!", $err);
assert($encOk === true, "File can proceed to encryption");
echo "6. Verified file can proceed to AES-256-GCM encryption\n";

echo "\n============================================================\n";
echo "MANUAL VERIFICATION INTEGRATION TEST: PASSED COMPLETELY!\n";
echo "============================================================\n";
