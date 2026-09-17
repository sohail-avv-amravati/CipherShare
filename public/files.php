<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Security\CSRF;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        if ($_POST['action'] === 'upload' && isset($_FILES['file'])) {
            $uploaded = FileManager::uploadFile($userId, $_FILES['file'], $error);
            if ($uploaded) {
                set_flash_message('success', 'File uploaded successfully.');
                redirect('/files.php');
            }
        } elseif ($_POST['action'] === 'delete' && isset($_POST['file_id'])) {
            $fileId = (int)$_POST['file_id'];
            if (FileManager::deleteFile($userId, $fileId, $error)) {
                set_flash_message('success', 'File deleted successfully.');
                redirect('/files.php');
            }
        }
    }
}

$userFiles = FileManager::getUserFiles($userId);
$pageTitle = "My Files";
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">My Files</h1>
        <p class="section-subtitle">Manage your uploaded files before sharing.</p>
    </div>
</div>

<?php if ($error): ?>
    <div class="alert alert-danger"><?= sanitize($error) ?></div>
<?php endif; ?>

<div class="card" style="margin-bottom: 30px; border: 2px dashed var(--border-color); background: transparent;">
    <form action="/files.php" method="POST" enctype="multipart/form-data" style="display: flex; flex-wrap: wrap; gap: 15px; align-items: center;">
        <?= CSRF::getFormField() ?>
        <input type="hidden" name="action" value="upload">
        <div style="flex-grow: 1;">
            <input type="file" name="file" id="file" class="form-control" required style="background: var(--card-bg);">
        </div>
        <button type="submit" class="btn btn-primary">?? Upload File</button>
    </form>
</div>

<?php if (empty($userFiles)): ?>
    <div class="empty-state">
        <div class="empty-state-icon">??</div>
        <div class="empty-state-text">No files uploaded yet</div>
        <div class="empty-state-sub">Upload a file above to get started.</div>
    </div>
<?php else: ?>
    <div class="card-grid">
        <?php foreach ($userFiles as $f): ?>
            <div class="card" style="display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; gap: 10px;">
                        <div style="font-size: 1.1rem; font-weight: 700; word-break: break-all;">
                            <?= sanitize($f['original_name']) ?>
                        </div>
                        <div>
                            <?php if ($f['is_encrypted']): ?>
                                <span class="badge badge-success">Encrypted</span>
                            <?php else: ?>
                                <span class="badge badge-blue">Standard</span>
                            <?php endif; ?>
                        </div>
                    </div>
                    <ul style="list-style: none; font-size: 0.9rem; margin-bottom: 20px; color: var(--text-muted);">
                        <li style="padding: 4px 0; border-bottom: 1px dashed var(--border-color); display: flex; justify-content: space-between;">
                            <span>Size:</span> <span><?= number_format($f['file_size'] / 1024, 2) ?> KB</span>
                        </li>
                        <li style="padding: 4px 0; border-bottom: 1px dashed var(--border-color); display: flex; justify-content: space-between;">
                            <span>Uploaded:</span> <span><?= date('d M Y, h:i A', strtotime($f['created_at'])) ?></span>
                        </li>
                    </ul>
                </div>
                <div style="display: flex; gap: 10px;">
                    <a href="/shares.php?file_id=<?= $f['id'] ?>" class="btn btn-primary btn-sm" style="flex: 1; text-align: center;">Share</a>
                    <form action="/files.php" method="POST" style="display: inline; flex: 1;" onsubmit="return confirm('Are you sure you want to delete this file?');">
                        <?= CSRF::getFormField() ?>
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="file_id" value="<?= $f['id'] ?>">
                        <button type="submit" class="btn btn-danger btn-sm" style="width: 100%;">Delete</button>
                    </form>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<?php include BASE_DIR . '/templates/footer.php'; ?>
