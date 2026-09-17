<?php
use Crypto\AES256GCM;

$plaintext = "CONFIDENTIAL CIPHERSHARE DATA CONTENT " . bin2hex(random_bytes(32));
$passphrase = "SecretKey#2026";

// 1. Encrypt Content
$container = AES256GCM::encryptFileContent($plaintext, $passphrase, "confidential.doc", "application/msword");
assertTest(substr($container, 0, 6) === "CSGCM1", "Crypto AES-256-GCM: Container features valid CSGCM1 magic header");

// 2. Decrypt Content
$decrypted = AES256GCM::decryptFileContent($container, $passphrase);
assertTest($decrypted['content'] === $plaintext, "Crypto AES-256-GCM: Decrypted content matches original binary bytes exactly");
assertTest($decrypted['filename'] === "confidential.doc", "Crypto AES-256-GCM: Container preserves original filename metadata");

// 3. Decrypt with Wrong Passphrase
$wrongFailed = false;
try {
    AES256GCM::decryptFileContent($container, "WrongPassphrase123!");
} catch (\Exception $e) {
    $wrongFailed = true;
}
assertTest($wrongFailed === true, "Crypto AES-256-GCM: Rejects decryption attempt with wrong passphrase");
