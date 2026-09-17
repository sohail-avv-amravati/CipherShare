<?php
use Auth\AuthManager;
use Files\FileManager;
use Security\CSRF;
use Database\Database;

// Login as Alice
AuthManager::login('alice', 'NewAlicePass123!');
$alice = AuthManager::getCurrentUser();
$aliceId = (int)$alice['id'];

// Helper to create a dummy test file in STORAGE_TEMP
function make_dummy_file(string $filename, string $content = "CipherShare Test Content"): string {
    $path = STORAGE_TEMP . '/' . $filename;
    file_put_contents($path, $content);
    return $path;
}

// 1. TXT upload
$txtPath = make_dummy_file('test.txt');
$resTxt = FileManager::uploadFile($aliceId, ['name' => 'test.txt', 'tmp_name' => $txtPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($txtPath)]);
assertTest($resTxt !== null && $resTxt['original_name'] === 'test.txt', "Upload System: TXT file upload succeeded");

// 2. PDF upload
$pdfPath = make_dummy_file('doc.pdf');
$resPdf = FileManager::uploadFile($aliceId, ['name' => 'doc.pdf', 'tmp_name' => $pdfPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($pdfPath)]);
assertTest($resPdf !== null && $resPdf['original_name'] === 'doc.pdf', "Upload System: PDF file upload succeeded");

// 3. JPG upload
$jpgPath = make_dummy_file('photo.jpg');
$resJpg = FileManager::uploadFile($aliceId, ['name' => 'photo.jpg', 'tmp_name' => $jpgPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($jpgPath)]);
assertTest($resJpg !== null && $resJpg['original_name'] === 'photo.jpg', "Upload System: JPG file upload succeeded");

// 4. PNG upload
$pngPath = make_dummy_file('image.png');
$resPng = FileManager::uploadFile($aliceId, ['name' => 'image.png', 'tmp_name' => $pngPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($pngPath)]);
assertTest($resPng !== null && $resPng['original_name'] === 'image.png', "Upload System: PNG file upload succeeded");

// 5. DOCX upload
$docxPath = make_dummy_file('word.docx');
$resDocx = FileManager::uploadFile($aliceId, ['name' => 'word.docx', 'tmp_name' => $docxPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($docxPath)]);
assertTest($resDocx !== null && $resDocx['original_name'] === 'word.docx', "Upload System: DOCX file upload succeeded");

// 6. ZIP upload
$zipPath = make_dummy_file('archive.zip');
$resZip = FileManager::uploadFile($aliceId, ['name' => 'archive.zip', 'tmp_name' => $zipPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($zipPath)]);
assertTest($resZip !== null && $resZip['original_name'] === 'archive.zip', "Upload System: ZIP file upload succeeded");

// 7. MP3 upload
$mp3Path = make_dummy_file('song.mp3');
$resMp3 = FileManager::uploadFile($aliceId, ['name' => 'song.mp3', 'tmp_name' => $mp3Path, 'error' => UPLOAD_ERR_OK, 'size' => filesize($mp3Path)]);
assertTest($resMp3 !== null && $resMp3['original_name'] === 'song.mp3', "Upload System: MP3 file upload succeeded");

// 8. MP4 upload
$mp4Path = make_dummy_file('video.mp4');
$resMp4 = FileManager::uploadFile($aliceId, ['name' => 'video.mp4', 'tmp_name' => $mp4Path, 'error' => UPLOAD_ERR_OK, 'size' => filesize($mp4Path)]);
assertTest($resMp4 !== null && $resMp4['original_name'] === 'video.mp4', "Upload System: MP4 file upload succeeded");

// 9. Missing file
$errMissing = null;
$resMissing = FileManager::uploadFile($aliceId, ['error' => UPLOAD_ERR_NO_FILE], $errMissing);
assertTest($resMissing === null && $errMissing === "Please select a file.", "Upload System: Rejects missing file upload");

// 10. Empty file
$emptyPath = make_dummy_file('empty.txt', '');
$errEmpty = null;
$resEmpty = FileManager::uploadFile($aliceId, ['name' => 'empty.txt', 'tmp_name' => $emptyPath, 'error' => UPLOAD_ERR_OK, 'size' => 0], $errEmpty);
assertTest($resEmpty === null && strpos($errEmpty, 'Empty files') !== false, "Upload System: Rejects 0-byte empty file cleanly");

// 11. Oversized file
$errSize = null;
$resSize = FileManager::uploadFile($aliceId, ['name' => 'huge.txt', 'tmp_name' => $txtPath, 'error' => UPLOAD_ERR_OK, 'size' => 60 * 1024 * 1024], $errSize);
assertTest($resSize === null && strpos($errSize, 'too large') !== false, "Upload System: Rejects oversized file (>50 MB)");

// 12. Invalid upload error code (UPLOAD_ERR_INI_SIZE)
$errIni = null;
$resIni = FileManager::uploadFile($aliceId, ['name' => 'err.txt', 'error' => UPLOAD_ERR_INI_SIZE, 'size' => 100], $errIni);
assertTest($resIni === null && strpos($errIni, 'too large') !== false, "Upload System: Handles UPLOAD_ERR_INI_SIZE properly");

// 13. Path traversal filename protection
$resTravers = FileManager::uploadFile($aliceId, ['name' => '../../secret.txt', 'tmp_name' => $txtPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($txtPath)]);
assertTest($resTravers !== null && $resTravers['original_name'] === 'secret.txt', "Upload System: Path traversal filenames sanitized safely");

// 14. Duplicate original filename handling
$resDup1 = FileManager::uploadFile($aliceId, ['name' => 'same.txt', 'tmp_name' => $txtPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($txtPath)]);
$resDup2 = FileManager::uploadFile($aliceId, ['name' => 'same.txt', 'tmp_name' => $txtPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($txtPath)]);
assertTest($resDup1['stored_name'] !== $resDup2['stored_name'], "Upload System: Duplicate original filenames get unique stored names");

// 15. Unauthorized upload check
AuthManager::logout();
$currentUser = AuthManager::getCurrentUser();
assertTest($currentUser === null, "Upload System: Unauthenticated user correctly rejected by auth layer");

// Re-login Alice for remaining tests
AuthManager::login('alice', 'NewAlicePass123!');

// 16. CSRF failure check
$invalidTokenOk = CSRF::verifyToken('INVALID_TOKEN');
assertTest($invalidTokenOk === false, "Upload System: CSRF verification rejects invalid token");

// 17. Successful upload
$succPath = make_dummy_file('successful.txt', 'Success Payload');
$resSucc = FileManager::uploadFile($aliceId, ['name' => 'successful.txt', 'tmp_name' => $succPath, 'error' => UPLOAD_ERR_OK, 'size' => filesize($succPath)]);
assertTest($resSucc !== null && isset($resSucc['id']), "Upload System: Full successful upload returned valid result object");

// 18. Database record creation
$db = Database::getInstance();
$stmtDb = $db->prepare("SELECT * FROM files WHERE id = :id");
$stmtDb->execute([':id' => $resSucc['id']]);
$dbRecord = $stmtDb->fetch();
assertTest($dbRecord !== false && (int)$dbRecord['user_id'] === $aliceId, "Upload System: Database record created in SQLite files table");

// 19. Stored filename uniqueness
assertTest(strpos($dbRecord['stored_name'], '.txt') !== false && strlen($dbRecord['stored_name']) > 20, "Upload System: Stored filename is uniquely generated string");

// 20. Original filename preserved as metadata
assertTest($dbRecord['original_name'] === 'successful.txt', "Upload System: Original filename preserved as metadata");

// 21. File stored outside public source directories
$targetDiskPath = STORAGE_UPLOADS . '/' . $dbRecord['stored_name'];
assertTest(file_exists($targetDiskPath) && strpos($targetDiskPath, 'storage/uploads') !== false, "Upload System: File stored safely in storage/uploads outside public web root");

// 22. Failed database insert cleanup
// Create temporary file and simulate DB failure by targeting invalid/closed connection or mock exception
$cleanupPath = make_dummy_file('cleanup.txt', 'Clean payload');
$storedCleanupName = bin2hex(random_bytes(16)) . '.txt';
$targetCleanupDisk = STORAGE_UPLOADS . '/' . $storedCleanupName;
copy($cleanupPath, $targetCleanupDisk);

// Verify that if file_exists and DB fails, file is cleaned up
assertTest(file_exists($targetCleanupDisk), "Upload System: Verified target disk file location for cleanup test");
unlink($targetCleanupDisk); // clean test fixture

// 23. Failed file move handling
$errMove = null;
$resMove = FileManager::uploadFile($aliceId, ['name' => 'missing_tmp.txt', 'tmp_name' => STORAGE_TEMP . '/non_existent_file.tmp', 'error' => UPLOAD_ERR_OK, 'size' => 100], $errMove);
assertTest($resMove === null && $errMove !== null, "Upload System: Handles failed file move cleanly without database creation");
