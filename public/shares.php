<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Shares\ShareManager;
use Security\CSRF;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;

$fileId = isset($_GET['file_id']) ? (int)$_GET['file_id'] : 0;
$userFiles = FileManager::getUserFiles($userId);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        $targetFileId = (int)($_POST['file_id'] ?? 0);
        $recipientUsername = trim($_POST['recipient_username'] ?? '');
        $durationKey = $_POST['duration'] ?? '1h';

        $shareId = ShareManager::createShare($userId, $targetFileId, $recipientUsername, $durationKey, $error);
        if ($shareId) {
            set_flash_message('success', "File share link created successfully for user '{$recipientUsername}'.");
            redirect('/sent-shares.php');
        }
    }
}

$pageTitle = "Share File";
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">Share File with User</h1>
        <p class="section-subtitle">Securely send a file to another user.</p>
    </div>
    <div>
        <a href="/sent-shares.php" class="btn btn-secondary btn-sm btn-inline">Sent Shares</a>
        <a href="/received-shares.php" class="btn btn-secondary btn-sm">Received Shares</a>
    </div>
</div>

<div class="card form-card" style="margin: 0; max-width: 600px;">
    <?php if ($error): ?>
        <div class="alert alert-danger"><?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/shares.php" method="POST">
        <?= CSRF::getFormField() ?>

        <div class="form-group">
            <label for="file_id">Select File to Share</label>
            <select name="file_id" id="file_id" class="form-control" required>
                <option value="">-- Choose File --</option>
                <?php foreach ($userFiles as $f): ?>
                    <option value="<?= $f['id'] ?>" <?= $f['id'] === $fileId ? 'selected' : '' ?>>
                        <?= sanitize($f['original_name']) ?> <?= $f['is_encrypted'] ? '(Encrypted)' : '' ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="form-group">
            <label for="recipient_username">Recipient Username</label>
            <input type="text" name="recipient_username" id="recipient_username" class="form-control" required placeholder="Exact recipient username" autocomplete="off">
            <small style="color: var(--text-muted);">Users are identified strictly by Username. No email required.</small>
        </div>

        <div class="form-group">
            <label for="duration">Server Expiration Period</label>
            <select name="duration" id="duration" class="form-control" required>
                <?php foreach (ShareManager::$expirationOptions as $key => $opt): ?>
                    <option value="<?= $key ?>"><?= sanitize($opt['label']) ?></option>
                <?php endforeach; ?>
            </select>
            <small style="color: var(--text-muted);">Expiration deadline is evaluated strictly against server time.</small>
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 15px; width: 100%;">Create Share</button>
    </form>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
