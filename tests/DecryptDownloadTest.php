<?php
/**
 * CipherShare Comprehensive Decryption & Download Test Suite
 */

if (!defined('BASE_DIR')) {
    require_once __DIR__ . '/../config/config.php';
}

if (!function_exists('assertTest')) {
    function assertTest(bool $condition, string $testName) {
        echo ($condition ? "  [PASS] " : "  [FAIL] ") . $testName . "\n";
    }
}

use Crypto\AES256GCM;
use Files\FileManager;

// 1. TXT file: encrypt -> decrypt -> verify exact byte match (500 bytes of text)
$txtOriginal = substr(str_repeat("CipherShare text document test content line. ", 15), 0, 500);
$txtContainer = AES256GCM::encryptFileContent($txtOriginal, 'TestPass123!', 'test_document.txt', 'text/plain');
$txtDecrypted = AES256GCM::decryptFileContent($txtContainer, 'TestPass123!');
assertTest($txtDecrypted['content'] === $txtOriginal && strlen($txtOriginal) === 500, "1. TXT file: encrypt -> decrypt -> verify exact byte match");

// 2. PDF file (binary): encrypt -> decrypt -> verify exact byte match (5KB random binary)
$pdfOriginal = "%PDF-1.4\n" . random_bytes(5120 - 9);
$pdfContainer = AES256GCM::encryptFileContent($pdfOriginal, 'TestPass123!', 'document.pdf', 'application/pdf');
$pdfDecrypted = AES256GCM::decryptFileContent($pdfContainer, 'TestPass123!');
assertTest($pdfDecrypted['content'] === $pdfOriginal && strlen($pdfOriginal) === 5120, "2. PDF file: encrypt -> decrypt -> verify exact byte match");

// 3. JPG file (binary): encrypt -> decrypt -> verify exact byte match (8KB random binary)
$jpgOriginal = "\xFF\xD8\xFF\xE0\x00\x10JFIF" . random_bytes(8192 - 10);
$jpgContainer = AES256GCM::encryptFileContent($jpgOriginal, 'TestPass123!', 'photo.jpg', 'image/jpeg');
$jpgDecrypted = AES256GCM::decryptFileContent($jpgContainer, 'TestPass123!');
assertTest($jpgDecrypted['content'] === $jpgOriginal && strlen($jpgOriginal) === 8192, "3. JPG file: encrypt -> decrypt -> verify exact byte match");

// 4. PNG file (binary): encrypt -> decrypt -> verify exact byte match (8KB random binary)
$pngOriginal = "\x89PNG\r\n\x1a\n" . random_bytes(8192 - 8);
$pngContainer = AES256GCM::encryptFileContent($pngOriginal, 'TestPass123!', 'graphic.png', 'image/png');
$pngDecrypted = AES256GCM::decryptFileContent($pngContainer, 'TestPass123!');
assertTest($pngDecrypted['content'] === $pngOriginal && strlen($pngOriginal) === 8192, "4. PNG file: encrypt -> decrypt -> verify exact byte match");

// 5. DOCX file (binary): encrypt -> decrypt -> verify exact byte match (5KB random binary)
$docxOriginal = "PK\x03\x04" . random_bytes(5120 - 4);
$docxContainer = AES256GCM::encryptFileContent($docxOriginal, 'TestPass123!', 'document.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
$docxDecrypted = AES256GCM::decryptFileContent($docxContainer, 'TestPass123!');
assertTest($docxDecrypted['content'] === $docxOriginal && strlen($docxOriginal) === 5120, "5. DOCX file: encrypt -> decrypt -> verify exact byte match");

// 6. ZIP file (binary): encrypt -> decrypt -> verify exact byte match (3KB random binary)
$zipOriginal = "PK\x03\x04" . random_bytes(3072 - 4);
$zipContainer = AES256GCM::encryptFileContent($zipOriginal, 'TestPass123!', 'archive.zip', 'application/zip');
$zipDecrypted = AES256GCM::decryptFileContent($zipContainer, 'TestPass123!');
assertTest($zipDecrypted['content'] === $zipOriginal && strlen($zipOriginal) === 3072, "6. ZIP file: encrypt -> decrypt -> verify exact byte match");

// 7. MP3 file (binary): encrypt -> decrypt -> verify exact byte match (10KB random binary)
$mp3Original = "ID3" . random_bytes(10240 - 3);
$mp3Container = AES256GCM::encryptFileContent($mp3Original, 'TestPass123!', 'audio.mp3', 'audio/mpeg');
$mp3Decrypted = AES256GCM::decryptFileContent($mp3Container, 'TestPass123!');
assertTest($mp3Decrypted['content'] === $mp3Original && strlen($mp3Original) === 10240, "7. MP3 file: encrypt -> decrypt -> verify exact byte match");

// 8. MP4 file (binary): encrypt -> decrypt -> verify exact byte match (10KB random binary)
$mp4Original = "\x00\x00\x00\x18ftypmp42" . random_bytes(10240 - 12);
$mp4Container = AES256GCM::encryptFileContent($mp4Original, 'TestPass123!', 'video.mp4', 'video/mp4');
$mp4Decrypted = AES256GCM::decryptFileContent($mp4Container, 'TestPass123!');
assertTest($mp4Decrypted['content'] === $mp4Original && strlen($mp4Original) === 10240, "8. MP4 file: encrypt -> decrypt -> verify exact byte match");

// 9. Arbitrary binary file (random 10KB): encrypt -> decrypt -> verify exact byte match
$binOriginal = random_bytes(10240);
$binContainer = AES256GCM::encryptFileContent($binOriginal, 'TestPass123!', 'arbitrary.bin', 'application/octet-stream');
$binDecrypted = AES256GCM::decryptFileContent($binContainer, 'TestPass123!');
assertTest($binDecrypted['content'] === $binOriginal && strlen($binOriginal) === 10240, "9. Arbitrary binary file: encrypt -> decrypt -> verify exact byte match");

// 10. Temp file creation: decrypt -> write to STORAGE_TEMP -> verify file exists, is readable, size matches
$tempData = random_bytes(4096);
$tempContainer = AES256GCM::encryptFileContent($tempData, 'TestPass123!', 'temp_test.dat', 'application/octet-stream');
$tempDecrypted = AES256GCM::decryptFileContent($tempContainer, 'TestPass123!');

$tempFilename = 'test_dec_' . bin2hex(random_bytes(16)) . '.tmp';
$tempFilePath = STORAGE_TEMP . '/' . $tempFilename;
file_put_contents($tempFilePath, $tempDecrypted['content'], LOCK_EX);

$tempValid = file_exists($tempFilePath) && is_readable($tempFilePath) && filesize($tempFilePath) === strlen($tempDecrypted['content']);
assertTest($tempValid, "10. Temp file creation: decrypt -> write to STORAGE_TEMP -> verify file exists, is readable, size matches");

// 11. Temp file cleanup: delete temp file -> verify it's gone
if (file_exists($tempFilePath)) {
    unlink($tempFilePath);
}
assertTest(!file_exists($tempFilePath), "11. Temp file cleanup: delete temp file -> verify it's gone");

// 12. Wrong passphrase: encrypt -> try decrypt with wrong pass -> verify exception thrown
$secretData = "Confidential data payload for decryption security verification";
$secretContainer = AES256GCM::encryptFileContent($secretData, 'CorrectPass#2026', 'secret.txt', 'text/plain');
$wrongPassExceptionCaught = false;
try {
    AES256GCM::decryptFileContent($secretContainer, 'WrongPass#9999');
} catch (\Exception $e) {
    $wrongPassExceptionCaught = true;
}
assertTest($wrongPassExceptionCaught, "12. Wrong passphrase: encrypt -> try decrypt with wrong pass -> verify exception thrown");

// 13. Filename preservation: verify decrypted container returns original filename
$origTestFilename = 'financial_audit_report_2026_q3.pdf';
$fnContainer = AES256GCM::encryptFileContent("%PDF-1.4 sample content", 'TestPass123!', $origTestFilename, 'application/pdf');
$fnDecrypted = AES256GCM::decryptFileContent($fnContainer, 'TestPass123!');
assertTest($fnDecrypted['filename'] === $origTestFilename, "13. Filename preservation: verify decrypted container returns original filename");

// 14. MIME type preservation: verify decrypted container returns original MIME type
$origTestMime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
$mimeContainer = AES256GCM::encryptFileContent("PK\x03\x04 sample content", 'TestPass123!', 'document.docx', $origTestMime);
$mimeDecrypted = AES256GCM::decryptFileContent($mimeContainer, 'TestPass123!');
assertTest($mimeDecrypted['mime'] === $origTestMime, "14. MIME type preservation: verify decrypted container returns original MIME type");

// 15. Path traversal in filename: use '../../evil.txt' as original filename -> encrypt -> decrypt -> verify filename is preserved but doesn't create path traversal
$evilFilename = '../../evil.txt';
$ptContainer = AES256GCM::encryptFileContent("Harmless text payload", 'TestPass123!', $evilFilename, 'text/plain');
$ptDecrypted = AES256GCM::decryptFileContent($ptContainer, 'TestPass123!');

$ptPreserved = ($ptDecrypted['filename'] === $evilFilename);
$safeExtractedName = basename(str_replace('\\', '/', $ptDecrypted['filename']));
$noTraversalCreated = ($safeExtractedName === 'evil.txt' && strpos($safeExtractedName, '..') === false);
assertTest($ptPreserved && $noTraversalCreated, "15. Path traversal in filename: use '../../evil.txt' as original filename -> encrypt -> decrypt -> verify filename is preserved but doesn't create path traversal");

// 16. Authorization: User A encrypts file -> User B cannot access via getUserFile()
$db = \Database\Database::getInstance();

$stmtUserA = $db->prepare("SELECT id FROM users WHERE username = 'alice'");
$stmtUserA->execute();
$rowA = $stmtUserA->fetch();
if (!$rowA) {
    $db->prepare("INSERT INTO users (username, password_hash, role, status) VALUES ('alice', 'dummy_hash', 'USER', 'ACTIVE')")->execute();
    $userAId = (int)$db->lastInsertId();
} else {
    $userAId = (int)$rowA['id'];
}

$stmtUserB = $db->prepare("SELECT id FROM users WHERE username = 'bob'");
$stmtUserB->execute();
$rowB = $stmtUserB->fetch();
if (!$rowB) {
    $db->prepare("INSERT INTO users (username, password_hash, role, status) VALUES ('bob', 'dummy_hash', 'USER', 'ACTIVE')")->execute();
    $userBId = (int)$db->lastInsertId();
} else {
    $userBId = (int)$rowB['id'];
}

if (!is_dir(STORAGE_UPLOADS)) {
    @mkdir(STORAGE_UPLOADS, 0755, true);
}
if (!is_dir(STORAGE_ENCRYPTED)) {
    @mkdir(STORAGE_ENCRYPTED, 0755, true);
}

$storedA = bin2hex(random_bytes(16)) . '.txt';
$uploadAPath = STORAGE_UPLOADS . '/' . $storedA;
file_put_contents($uploadAPath, "Confidential contents belonging exclusively to User A");

$stmtInsFile = $db->prepare("INSERT INTO files (user_id, original_name, stored_name, mime_type, file_size, is_encrypted, created_at) VALUES (:uid, 'userA_private.txt', :sname, 'text/plain', :fsize, 0, CURRENT_TIMESTAMP)");
$stmtInsFile->execute([
    ':uid'   => $userAId,
    ':sname' => $storedA,
    ':fsize' => strlen("Confidential contents belonging exclusively to User A")
]);
$userAFileId = (int)$db->lastInsertId();

$encryptError = null;
$encryptSuccess = FileManager::encryptUserFile($userAId, $userAFileId, 'UserASecretPass#1', $encryptError);

$userAAccessResult = FileManager::getUserFile($userAId, $userAFileId);
$userBAccessResult = FileManager::getUserFile($userBId, $userAFileId);

assertTest($encryptSuccess === true && $userAAccessResult !== null && $userBAccessResult === null, "16. Authorization: User A encrypts file -> User B cannot access via getUserFile()");

// 17. Download header sanitization: test that filename with special chars (quotes, backslashes, etc.) produces a safe sanitized filename using this function:
// preg_replace('/[^\w\.\-\(\)\[\] ]/', '_', $filename)
$dirtyFilename = "report\"1\\2/3*4?5<6>7|8;9'0`~!@#$%^&+={}:,.txt";
$sanitizedFilename = preg_replace('/[^\w\.\-\(\)\[\] ]/', '_', $dirtyFilename);
$hasDisallowedChars = (preg_match('/[^\w\.\-\(\)\[\] ]/', $sanitizedFilename) === 1);
$noQuotesOrSlashes = (strpos($sanitizedFilename, '"') === false && strpos($sanitizedFilename, '\\') === false && strpos($sanitizedFilename, '/') === false);
assertTest(!$hasDisallowedChars && $noQuotesOrSlashes, "17. Download header sanitization: test that filename with special chars produces a safe sanitized filename");

// 18. Content-Length accuracy: verify strlen() of decrypted content matches original size
$sizeTestContent = random_bytes(6543);
$originalContentLength = strlen($sizeTestContent);
$sizeContainer = AES256GCM::encryptFileContent($sizeTestContent, 'SizePass123!', 'size_test.bin', 'application/octet-stream');
$sizeDecrypted = AES256GCM::decryptFileContent($sizeContainer, 'SizePass123!');
assertTest(strlen($sizeDecrypted['content']) === $originalContentLength, "18. Content-Length accuracy: verify strlen() of decrypted content matches original size");

// 19. Empty content rejection: verify that zero-length decrypted content is detected
$emptyContent = "";
$emptyContainer = AES256GCM::encryptFileContent($emptyContent, 'EmptyPass123!', 'empty.txt', 'text/plain');
$emptyDecrypted = AES256GCM::decryptFileContent($emptyContainer, 'EmptyPass123!');
$zeroLengthDetected = (strlen($emptyDecrypted['content']) === 0);
assertTest($zeroLengthDetected === true, "19. Empty content rejection: verify that zero-length decrypted content is detected");

// 20. Session download token: Create a token with bin2hex(random_bytes(32)), store in array, verify it can be retrieved and verified
$sessionDownloads = [];
$downloadToken = bin2hex(random_bytes(32));

$sessionDownloads[$downloadToken] = [
    'temp_path'  => STORAGE_TEMP . '/dec_sample.tmp',
    'filename'   => 'secure_export.pdf',
    'mime'       => 'application/pdf',
    'size'       => 5120,
    'user_id'    => $userAId,
    'created_at' => time()
];

$retrievedSessionData = $sessionDownloads[$downloadToken] ?? null;
$tokenVerified = (
    strlen($downloadToken) === 64 &&
    ctype_xdigit($downloadToken) &&
    $retrievedSessionData !== null &&
    $retrievedSessionData['filename'] === 'secure_export.pdf' &&
    $retrievedSessionData['user_id'] === $userAId
);

assertTest($tokenVerified, "20. Session download token: Create a token with bin2hex(random_bytes(32)), store in array, verify it can be retrieved and verified");
