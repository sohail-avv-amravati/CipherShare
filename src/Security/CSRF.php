<?php
namespace Security;

class CSRF {
    public static function generateToken(): string {
        start_secure_session();
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyToken(?string $token): bool {
        start_secure_session();
        if (empty($_SESSION['csrf_token'])) {
            self::generateToken();
            return false;
        }
        if (empty($token)) {
            return false;
        }
        return hash_equals($_SESSION['csrf_token'], trim($token));
    }

    public static function getFormField(): string {
        $token = self::generateToken();
        return '<input type="hidden" name="csrf_token" value="' . sanitize($token) . '">';
    }
}