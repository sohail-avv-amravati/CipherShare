<?php
namespace Crypto;

class AES256GCM {

    /**
     * Encrypt a file's raw binary content using AES-256-GCM.
     * Returns an authenticated container binary stream containing header metadata + tag + ciphertext.
     */
    public static function encryptFileContent(string $plaintext, string $passphrase, string $originalFilename, string $mimeType): string {
        $cipher = "aes-256-gcm";
        if (!in_array($cipher, openssl_get_cipher_methods())) {
            throw new \Exception("AES-256-GCM cipher method is not supported on this PHP installation.");
        }

        // Generate cryptographically secure salt and nonce (12 bytes for GCM)
        $salt = random_bytes(16);
        $nonce = random_bytes(12);

        // Derive 256-bit key using PBKDF2 with SHA-256
        $key = hash_pbkdf2("sha256", $passphrase, $salt, 10000, 32, true);

        $tag = "";
        $ciphertext = openssl_encrypt(
            $plaintext,
            $cipher,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            "",
            16
        );

        if ($ciphertext === false) {
            throw new \Exception("Encryption failed.");
        }

        // Build container metadata
        $meta = [
            'v' => 1,
            'alg' => 'AES-256-GCM',
            'filename' => $originalFilename,
            'mime' => $mimeType,
            'size' => strlen($plaintext),
            'salt' => bin2hex($salt),
            'nonce' => bin2hex($nonce),
            'tag' => bin2hex($tag)
        ];

        $jsonMeta = json_encode($meta, JSON_UNESCAPED_SLASHES);
        $metaLen = pack('N', strlen($jsonMeta)); // 4 bytes unsigned long big-endian

        // Binary structure: Magic "CSGCM1" (6 bytes) + MetaLen (4 bytes) + JSON Meta + Ciphertext
        return "CSGCM1" . $metaLen . $jsonMeta . $ciphertext;
    }

    /**
     * Decrypt container content using passphrase.
     * Returns array ['content' => binary, 'filename' => string, 'mime' => string]
     */
    public static function decryptFileContent(string $containerData, string $passphrase): array {
        if (strlen($containerData) < 10 || substr($containerData, 0, 6) !== "CSGCM1") {
            throw new \Exception("Invalid or unrecognized CipherShare encrypted file format.");
        }

        $metaLenArray = unpack('Nlen', substr($containerData, 6, 4));
        $metaLen = $metaLenArray['len'];

        $jsonMeta = substr($containerData, 10, $metaLen);
        $ciphertext = substr($containerData, 10 + $metaLen);

        $meta = json_decode($jsonMeta, true);
        if (!$meta || empty($meta['salt']) || empty($meta['nonce']) || empty($meta['tag'])) {
            throw new \Exception("Corrupted container metadata.");
        }

        $salt = hex2bin($meta['salt']);
        $nonce = hex2bin($meta['nonce']);
        $tag = hex2bin($meta['tag']);

        // Derive 256-bit key
        $key = hash_pbkdf2("sha256", $passphrase, $salt, 10000, 32, true);

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag
        );

        if ($plaintext === false) {
            throw new \Exception("Decryption failed. Incorrect passphrase or file corrupted.");
        }

        return [
            'content' => $plaintext,
            'filename' => $meta['filename'] ?? 'decrypted_file',
            'mime' => $meta['mime'] ?? 'application/octet-stream'
        ];
    }
}
