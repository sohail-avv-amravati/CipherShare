<?php
namespace Auth;

use Database\Database;
use Security\AuditLogger;
use Security\SecurityQuestions;
use PDO;

class AuthManager {

    /**
     * Validate password policy: minimum 8 characters, allows uppercase, lowercase, numbers, symbols
     */
    public static function validatePassword(string $password, string $confirmPassword, ?string &$error = null): bool {
        if ($password !== $confirmPassword) {
            $error = "Passwords do not match.";
            return false;
        }

        if (mb_strlen($password) < 8) {
            $error = "Password must be at least 8 characters long.";
            return false;
        }

        if (!preg_match('/[a-zA-Z]/', $password) || !preg_match('/[0-9\W]/', $password)) {
            $error = "Password should contain a mixture of letters and numbers/symbols.";
            return false;
        }

        return true;
    }

    /**
     * Register a new user
     */
    public static function register(string $username, string $password, string $confirmPassword, array $questionAnswers, ?string &$error = null): bool {
        $username = trim($username);

        if (empty($username) || mb_strlen($username) < 3 || mb_strlen($username) > 30) {
            $error = "Username must be between 3 and 30 characters.";
            return false;
        }

        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
            $error = "Username can only contain letters, numbers, underscores, and hyphens.";
            return false;
        }

        if (!self::validatePassword($password, $confirmPassword, $error)) {
            return false;
        }

        if (count($questionAnswers) !== 5) {
            $error = "You must answer all 5 security questions.";
            return false;
        }

        foreach ($questionAnswers as $qId => $ans) {
            if (empty(trim((string)$ans))) {
                $error = "All 5 security questions must have valid answers.";
                return false;
            }
        }

        $db = Database::getInstance();

        $stmt = $db->prepare("SELECT id FROM users WHERE LOWER(username) = LOWER(:username)");
        $stmt->execute([':username' => $username]);
        if ($stmt->fetch()) {
            $error = "Username is already taken. Please choose another.";
            return false;
        }

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $db->beginTransaction();
        try {
            $stmtUser = $db->prepare("INSERT INTO users (username, password_hash, role, status, created_at) VALUES (:username, :password_hash, 'USER', 'ACTIVE', CURRENT_TIMESTAMP)");
            $stmtUser->execute([
                ':username' => $username,
                ':password_hash' => $passwordHash
            ]);

            $userId = (int)$db->lastInsertId();

            if (!SecurityQuestions::assignUserQuestions($userId, $questionAnswers)) {
                throw new \Exception("Failed to save security questions.");
            }

            $db->commit();

            AuditLogger::logEvent(
                $userId,
                $username,
                'USER',
                'AUTH',
                'USER_REGISTERED',
                $userId,
                null,
                null,
                "New user account registered: {$username}"
            );

            return true;
        } catch (\Exception $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            $error = "Registration failed due to a system error. Please try again.";
            return false;
        }
    }

    /**
     * Login user
     */
    public static function login(string $username, string $password, ?string &$error = null): bool {
        start_secure_session();
        $username = trim($username);

        if (empty($username) || empty($password)) {
            $error = "Please enter both username and password.";
            return false;
        }

        if (self::isRateLimited($username, 'login', 5, 300)) {
            $error = "Too many failed login attempts. Please wait 5 minutes before trying again.";
            AuditLogger::logSecurityEvent(null, "LOGIN_RATE_LIMITED", "IP rate limited for username: {$username}");
            return false;
        }

        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT id, username, password_hash, role, status FROM users WHERE LOWER(username) = LOWER(:username)");
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            self::recordAttempt($username, 0);
            AuditLogger::logSecurityEvent(
                $user['id'] ?? null,
                "FAILED_LOGIN",
                "Failed login attempt for username: {$username}"
            );
            $error = "Invalid username or password.";
            return false;
        }

        if ($user['status'] === 'SUSPENDED') {
            $error = "Your account has been suspended by the administrator. Contact support.";
            AuditLogger::logSecurityEvent($user['id'], "LOGIN_SUSPENDED_BLOCKED", "Suspended user '{$user['username']}' attempted login");
            return false;
        }

        if ($user['status'] === 'DEACTIVATED') {
            $error = "Your account has been deactivated.";
            AuditLogger::logSecurityEvent($user['id'], "LOGIN_DEACTIVATED_BLOCKED", "Deactivated user '{$user['username']}' attempted login");
            return false;
        }

        self::recordAttempt($username, 1);

        // Update last login timestamp
        $stmtLast = $db->prepare("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id");
        $stmtLast->execute([':id' => $user['id']]);

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }

        $_SESSION['user_id'] = (int)$user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['logged_in_at'] = time();

        $category = ($user['role'] === 'OWNER') ? 'OWNER' : 'AUTH';
        $eventType = ($user['role'] === 'OWNER') ? 'OWNER_LOGIN' : 'USER_LOGIN';

        AuditLogger::logEvent(
            (int)$user['id'],
            $user['username'],
            $user['role'],
            $category,
            $eventType,
            (int)$user['id'],
            null,
            null,
            "{$user['role']} logged in: {$user['username']}"
        );

        return true;
    }

    /**
     * Rate limiting helper using login_attempts table
     */
    public static function isRateLimited(string $identifier, string $type, int $maxAttempts, int $timeWindowSeconds): bool {
        $db = Database::getInstance();
        $stmt = $db->prepare("
            SELECT COUNT(*) AS cnt 
            FROM login_attempts 
            WHERE identifier = :identifier 
              AND success = 0 
              AND attempted_at >= datetime('now', :offset)
        ");
        $stmt->execute([
            ':identifier' => $type . ':' . strtolower($identifier),
            ':offset' => "-{$timeWindowSeconds} seconds"
        ]);
        $row = $stmt->fetch();
        return ((int)($row['cnt'] ?? 0)) >= $maxAttempts;
    }

    public static function recordAttempt(string $identifier, int $success, string $type = 'login'): void {
        $db = Database::getInstance();
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $stmt = $db->prepare("INSERT INTO login_attempts (identifier, ip_address, attempted_at, success) VALUES (:identifier, :ip, CURRENT_TIMESTAMP, :success)");
        $stmt->execute([
            ':identifier' => $type . ':' . strtolower($identifier),
            ':ip' => $ip,
            ':success' => $success
        ]);
    }

    /**
     * Start password reset flow
     */
    public static function initiatePasswordReset(string $username, ?string &$error = null): ?array {
        $username = trim($username);

        if (empty($username)) {
            $error = "Please enter your username.";
            return null;
        }

        if (self::isRateLimited($username, 'reset_init', 5, 300)) {
            $error = "Too many password reset requests. Please try again later.";
            return null;
        }

        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT id, username, status, role FROM users WHERE LOWER(username) = LOWER(:username)");
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch();

        if (!$user) {
            self::recordAttempt($username, 0, 'reset_init');
            $error = "Invalid username.";
            return null;
        }

        if ($user['status'] !== 'ACTIVE') {
            $error = "Account is not active.";
            return null;
        }

        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', time() + 900);

        $stmtSession = $db->prepare("INSERT INTO password_reset_sessions (token, user_id, expires_at, is_verified, attempts, used, created_at) VALUES (:token, :user_id, :expires_at, 0, 0, 0, CURRENT_TIMESTAMP)");
        $stmtSession->execute([
            ':token' => $token,
            ':user_id' => $user['id'],
            ':expires_at' => $expiresAt
        ]);

        AuditLogger::logEvent(
            (int)$user['id'],
            $user['username'],
            $user['role'],
            'AUTH',
            'PASSWORD_RESET_STARTED',
            (int)$user['id'],
            null,
            null,
            "Password reset session initiated for username: {$user['username']}"
        );

        return [
            'token' => $token,
            'user_id' => (int)$user['id'],
            'username' => $user['username']
        ];
    }

    /**
     * Verify security answers for password reset
     */
    public static function verifyPasswordResetAnswers(string $token, array $submittedAnswers, ?string &$error = null): bool {
        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT prs.*, u.username, u.role FROM password_reset_sessions prs JOIN users u ON u.id = prs.user_id WHERE prs.token = :token AND prs.used = 0");
        $stmt->execute([':token' => $token]);
        $session = $stmt->fetch();

        if (!$session) {
            $error = "Invalid or expired password reset session.";
            return false;
        }

        if (strtotime($session['expires_at']) < time()) {
            $error = "Password reset session has expired. Please try again.";
            return false;
        }

        if ($session['attempts'] >= 3) {
            $error = "Maximum verification attempts exceeded. Please restart password recovery.";
            AuditLogger::logSecurityEvent($session['user_id'], "REPEATED_PASSWORD_RESET_FAILURES", "Password reset session locked due to repeated failures");
            return false;
        }

        $userId = (int)$session['user_id'];

        $stmtInc = $db->prepare("UPDATE password_reset_sessions SET attempts = attempts + 1 WHERE id = :id");
        $stmtInc->execute([':id' => $session['id']]);

        if (!SecurityQuestions::verifyUserAnswers($userId, $submittedAnswers)) {
            AuditLogger::logSecurityEvent($userId, "PASSWORD_RESET_FAILED", "Failed security question verification during password reset");
            $error = "Security verification failed.";
            return false;
        }

        $stmtVerify = $db->prepare("UPDATE password_reset_sessions SET is_verified = 1 WHERE id = :id");
        $stmtVerify->execute([':id' => $session['id']]);

        AuditLogger::logEvent(
            $userId,
            $session['username'],
            $session['role'],
            'AUTH',
            'PASSWORD_RESET_VERIFIED',
            $userId,
            null,
            null,
            "Security questions successfully verified for password reset"
        );

        return true;
    }

    /**
     * Complete password reset by setting new password
     */
    public static function completePasswordReset(string $token, string $newPassword, string $confirmPassword, ?string &$error = null): bool {
        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT prs.*, u.username, u.role FROM password_reset_sessions prs JOIN users u ON u.id = prs.user_id WHERE prs.token = :token AND prs.used = 0 AND prs.is_verified = 1");
        $stmt->execute([':token' => $token]);
        $session = $stmt->fetch();

        if (!$session || strtotime($session['expires_at']) < time()) {
            $error = "Invalid or expired password reset authorization.";
            return false;
        }

        if (!self::validatePassword($newPassword, $confirmPassword, $error)) {
            return false;
        }

        $userId = (int)$session['user_id'];
        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

        $db->beginTransaction();
        try {
            $stmtUser = $db->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
            $stmtUser->execute([':hash' => $newHash, ':id' => $userId]);

            $stmtMark = $db->prepare("UPDATE password_reset_sessions SET used = 1 WHERE id = :id");
            $stmtMark->execute([':id' => $session['id']]);

            $db->commit();

            AuditLogger::logEvent(
                $userId,
                $session['username'],
                $session['role'],
                'AUTH',
                'PASSWORD_RESET_COMPLETED',
                $userId,
                null,
                null,
                "Password successfully updated via security question reset"
            );

            return true;
        } catch (\Exception $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            $error = "Failed to update password.";
            return false;
        }
    }

    /**
     * Account Password Change (for logged-in user)
     */
    public static function changePassword(int $userId, string $currentPassword, string $newPassword, string $confirmPassword, ?string &$error = null): bool {
        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT username, role, password_hash FROM users WHERE id = :id");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($currentPassword, $user['password_hash'])) {
            $error = "Current password is incorrect.";
            return false;
        }

        if (!self::validatePassword($newPassword, $confirmPassword, $error)) {
            return false;
        }

        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmtUpdate = $db->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
        $stmtUpdate->execute([':hash' => $newHash, ':id' => $userId]);

        AuditLogger::logEvent(
            $userId,
            $user['username'],
            $user['role'],
            'AUTH',
            'PASSWORD_CHANGED',
            $userId,
            null,
            null,
            "User changed password from account settings"
        );

        return true;
    }

    public static function logout(): void {
        start_secure_session();
        $userId = $_SESSION['user_id'] ?? null;
        $username = $_SESSION['username'] ?? null;
        $role = $_SESSION['role'] ?? 'USER';

        if ($userId) {
            $category = ($role === 'OWNER') ? 'OWNER' : 'AUTH';
            $eventType = ($role === 'OWNER') ? 'OWNER_LOGOUT' : 'USER_LOGOUT';
            AuditLogger::logEvent(
                (int)$userId,
                $username,
                $role,
                $category,
                $eventType,
                (int)$userId,
                null,
                null,
                "{$role} logged out: {$username}"
            );
        }

        $_SESSION = [];
        if (ini_get("session.use_cookies") && !headers_sent()) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            @session_destroy();
        }
    }

    public static function getCurrentUser(): ?array {
        start_secure_session();
        if (empty($_SESSION['user_id'])) {
            return null;
        }

        $db = Database::getInstance();
        $stmt = $db->prepare("SELECT id, username, role, status, created_at, last_login_at FROM users WHERE id = :id");
        $stmt->execute([':id' => $_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (!$user || $user['status'] !== 'ACTIVE') {
            self::logout();
            return null;
        }

        return $user;
    }

    public static function requireLogin(): array {
        $user = self::getCurrentUser();
        if (!$user) {
            set_flash_message('danger', 'Please login to access this page.');
            redirect('/login.php');
        }
        return $user;
    }

    public static function requireOwner(): array {
        $user = self::requireLogin();
        if ($user['role'] !== 'OWNER') {
            AuditLogger::logEvent(
                $user['id'],
                $user['username'],
                $user['role'],
                'SECURITY',
                'UNAUTHORIZED_ACCESS_ATTEMPT',
                null,
                null,
                null,
                "Unauthorized attempt to access owner portal by user: {$user['username']}"
            );
            set_flash_message('danger', 'Access denied. Administrator privilege required.');
            redirect('/dashboard.php');
        }
        return $user;
    }
}
