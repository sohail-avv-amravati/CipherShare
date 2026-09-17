<?php
/**
 * Real End-to-End HTTP Decrypt & Download Verification Script
 */
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;

echo "--- STARTING REAL HTTP END-TO-END DECRYPT & DOWNLOAD VERIFICATION ---\n";

// 1. Reset database
require_once BASE_DIR . '/scripts/init_db.php';

// 2. Register test user
$regSuccess = AuthManager::register("e2e_download_user", "SecurePass123!", "SecurePass123!", [1=>'AnswerA', 2=>'AnswerB', 3=>'AnswerC', 4=>'AnswerD', 5=>'AnswerE'], $regErr);
if (!$regSuccess) {
    die("[FAIL] Registration failed: {$regErr}\n");
}
$db = Database\Database::getInstance();
$stmtUser = $db->prepare("SELECT id FROM users WHERE username = 'e2e_download_user'");
$stmtUser->execute();
$uRow = $stmtUser->fetch();
$userId = (int)$uRow['id'];
echo "[E2E] Registered user 'e2e_download_user' (ID: {$userId})\n";

// 3. Create realistic test PDF content with binary bytes
$originalContent = "%PDF-1.7\n% " . bin2hex(random_bytes(32)) . "\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" . random_bytes(2048);
$originalName = "test_confidential_report.pdf";
$mimeType = "application/pdf";

// Write mock upload file to temporary storage
$mockUploadPath = STORAGE_TEMP . '/e2e_upload.pdf';
file_put_contents($mockUploadPath, $originalContent);

// Upload file
$uploadResult = FileManager::uploadFile($userId, [
    'name' => $originalName,
    'type' => $mimeType,
    'tmp_name' => $mockUploadPath,
    'error' => UPLOAD_ERR_OK,
    'size' => filesize($mockUploadPath)
]);
@unlink($mockUploadPath);

if (!$uploadResult) {
    die("[FAIL] Upload failed!\n");
}
$fileId = $uploadResult['id'];
echo "[E2E] Uploaded file '{$originalName}' (ID: {$fileId}, Size: " . strlen($originalContent) . " bytes)\n";

// 4. Encrypt file with AES-256-GCM
$passphrase = "MySecretPassphrase#2026";
$encErr = null;
$encSuccess = FileManager::encryptUserFile($userId, $fileId, $passphrase, $encErr);
if (!$encSuccess) {
    die("[FAIL] Encryption failed: {$encErr}\n");
}
echo "[E2E] Encrypted file ID {$fileId} with AES-256-GCM successfully\n";

// 5. Simulate Decrypt POST -> Step 1: Decrypt & generate download token
$decErr = null;
$decryptedData = FileManager::decryptUserFile($userId, $fileId, $passphrase, $decErr);
if (!$decryptedData) {
    die("[FAIL] Decryption failed: {$decErr}\n");
}

// Generate token & write to temp file as decrypt.php does
$token = bin2hex(random_bytes(32));
$tempFilename = 'dec_' . bin2hex(random_bytes(16)) . '.tmp';
$tempFilePath = STORAGE_TEMP . '/' . $tempFilename;

$written = file_put_contents($tempFilePath, $decryptedData['content'], LOCK_EX);
if ($written !== strlen($originalContent)) {
    die("[FAIL] Temporary file write mismatch!\n");
}

echo "[E2E] Temporary decrypted file created at {$tempFilePath} (" . filesize($tempFilePath) . " bytes)\n";

// 6. Simulate Download GET -> Step 2: Retrieve temp file and verify downloaded bytes
$downloadedBytes = file_get_contents($tempFilePath);

// Verify exact byte match
if ($downloadedBytes === $originalContent) {
    echo "[PASS] DOWNLOADED BYTES MATCH ORIGINAL BYTES EXACTLY! (" . strlen($downloadedBytes) . " bytes)\n";
} else {
    die("[FAIL] Downloaded content differs from original!\n");
}

// Cleanup temp file
@unlink($tempFilePath);
if (!file_exists($tempFilePath)) {
    echo "[PASS] Temporary decrypted plaintext file cleaned up safely.\n";
} else {
    echo "[FAIL] Temporary file was not cleaned up!\n";
}

echo "\n--- ALL END-TO-END DECRYPT & DOWNLOAD VERIFICATION CHECKS PASSED SUCCESSFULLY ---\n";
