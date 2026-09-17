<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Security\CSRF;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF validation failed. Please try again.";
    } elseif (isset($_FILES['file'])) {
        $uploaded = FileManager::uploadFile($userId, $_FILES['file'], $error);
        if ($uploaded) {
            set_flash_message('success', "File '{$uploaded['original_name']}' uploaded successfully.");
            redirect('/files.php');
        }
    } else {
        $error = "No file selected.";
    }
}

$pageTitle = "Upload File";
include BASE_DIR . '/templates/header.php';
?>

<div class="card form-card">
    <h2 class="card-title" style="font-size: 1.6rem; text-align: center; margin-bottom: 20px;">Upload File</h2>
    <p style="color: var(--text-muted); text-align: center; margin-bottom: 24px;">
        Upload files securely. Supported extensions: TXT, PDF, JPG, PNG, DOCX, XLSX, ZIP, MP3, MP4, etc.
    </p>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= sanitize($error) ?></div>
    <?php endif; ?>

    <form action="/upload.php" method="POST" enctype="multipart/form-data">
        <?= CSRF::getFormField() ?>

        <div class="form-group">
            <label for="file">Choose File</label>
            <input type="file" id="file" name="file" class="form-control" required style="padding: 10px;">
            <small style="color: var(--text-muted);">Maximum file size limit: 50 MB.</small>
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 15px;">Upload File</button>
    </form>

    <div style="text-align: center; margin-top: 20px;">
        <a href="/files.php">Back to My Files</a>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
