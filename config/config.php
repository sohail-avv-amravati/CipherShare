<?php
/**
 * CipherShare Application Configuration
 */

define('BASE_DIR', dirname(__DIR__));
define('DB_PATH', BASE_DIR . '/database/ciphershare.sqlite');
define('STORAGE_UPLOADS', BASE_DIR . '/storage/uploads');
define('STORAGE_ENCRYPTED', BASE_DIR . '/storage/encrypted');
define('STORAGE_TEMP', BASE_DIR . '/storage/temporary');

define('APP_NAME', 'CipherShare');
define('OWNER_EMAIL', 'ciphershare.support@gmail.com');
define('SESSION_LIFETIME', 86400); // 24 hours

// Support Reverse Proxy HTTPS detection
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
    $_SERVER['HTTPS'] = 'on';
}

// Ensure required storage directories exist
foreach ([STORAGE_UPLOADS, STORAGE_ENCRYPTED, STORAGE_TEMP] as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
}

// Autoload src classes
spl_autoload_register(function ($class) {
    $base_dir = BASE_DIR . '/src/';
    $file = $base_dir . str_replace('\\', '/', $class) . '.php';
    if (file_exists($file)) {
        require_once $file;
    }
});

// Helper functions
if (!function_exists('start_secure_session')) {
    function start_secure_session() {
        if (session_status() === PHP_SESSION_NONE) {
            if (!headers_sent()) {
                @session_save_path(STORAGE_TEMP);
                ini_set('session.use_strict_mode', 0);
                ini_set('session.cookie_httponly', 1);
                ini_set('session.cookie_samesite', 'Lax');
                ini_set('session.gc_maxlifetime', 86400);
            }
            @session_start();
        }
    }
}

if (!function_exists('sanitize')) {
    function sanitize($data) {
        return htmlspecialchars(trim((string)$data), ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('redirect')) {
    function redirect($url) {
        if (!headers_sent()) {
            header("Location: " . $url);
            exit;
        }
    }
}

if (!function_exists('set_flash_message')) {
    function set_flash_message($type, $message) {
        start_secure_session();
        $_SESSION['flash'] = [
            'type' => $type,
            'message' => $message
        ];
    }
}

if (!function_exists('get_flash_message')) {
    function get_flash_message() {
        start_secure_session();
        if (isset($_SESSION['flash'])) {
            $flash = $_SESSION['flash'];
            unset($_SESSION['flash']);
            return $flash;
        }
        return null;
    }
}

if (!function_exists('format_file_size')) {
    function format_file_size($bytes) {
        $units = ['B', 'KB', 'MB', 'GB'];
        $bytes = max((int)$bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min((int)$pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, 2) . ' ' . $units[$pow];
    }
}