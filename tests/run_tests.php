<?php
/**
 * CipherShare Automated Test Runner
 */

define('TEST_MODE', true);
require_once __DIR__ . '/../config/config.php';

// Reset clean test database
if (file_exists(DB_PATH)) {
    unlink(DB_PATH);
}

require_once BASE_DIR . '/scripts/init_db.php';
require_once BASE_DIR . '/scripts/init_owner.php';

$totalPassed = 0;
$totalFailed = 0;

function assertTest(bool $condition, string $testName) {
    global $totalPassed, $totalFailed;
    if ($condition) {
        echo "  [PASS] {$testName}\n";
        $totalPassed++;
    } else {
        echo "  [FAIL] {$testName}\n";
        $totalFailed++;
    }
}

echo "\n============================================================\n";
echo "RUNNING CIPHERSHARE AUTOMATED TEST SUITE\n";
echo "============================================================\n";

$testFiles = [
    'AuthTest.php',
    'SecurityQuestionsTest.php',
    'PasswordResetTest.php',
    'CryptoTest.php',
    'ClassicalCiphersTest.php',
    'FilesTest.php',
    'FileUploadTest.php',
    'SharesTest.php',
    'ReceivedSharesTest.php',
    'DecryptDownloadTest.php',
    'OwnerTest.php',
    'SecurityAuditTest.php'
];

foreach ($testFiles as $tf) {
    echo "\nExecuting {$tf}...\n";
    require_once __DIR__ . '/' . $tf;
}

echo "\n============================================================\n";
echo "TEST RESULTS SUMMARY:\n";
echo "PASSED: {$totalPassed}\n";
echo "FAILED: {$totalFailed}\n";
echo "TOTAL:  " . ($totalPassed + $totalFailed) . "\n";
echo "============================================================\n";

if ($totalFailed > 0) {
    exit(1);
} else {
    exit(0);
}
