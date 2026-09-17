<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Shares\ShareManager;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];

// Get quick stats
$userFiles = FileManager::getUserFiles($userId);
$sentShares = ShareManager::getSentShares($userId);
$receivedShares = ShareManager::getReceivedShares($userId);

$totalFiles = count($userFiles);
$encryptedFiles = count(array_filter($userFiles, fn($f) => $f['is_encrypted']));

$totalSent = count($sentShares);
$sentSuccess = count(array_filter($sentShares, fn($s) => $s['status'] === 'SUCCESS'));
$sentPending = count(array_filter($sentShares, fn($s) => $s['status'] === 'PENDING'));

$pageTitle = "Dashboard";
include BASE_DIR . '/templates/header.php';
?>

<div class="section-header">
    <div>
        <h1 class="section-title">Hello, <?= sanitize($user['username']) ?> ??</h1>
        <p class="section-subtitle"><?= date('l, F j, Y') ?></p>
    </div>
</div>

<div class="card-grid" style="margin-bottom: 30px;">
    <div class="card stat-card">
        <div class="stat-icon" style="color: var(--primary);">??</div>
        <div class="stat-content">
            <div class="stat-value"><?= $totalFiles ?></div>
            <div class="stat-label">Total Files</div>
        </div>
    </div>
    <div class="card stat-card">
        <div class="stat-icon" style="color: var(--success);">??</div>
        <div class="stat-content">
            <div class="stat-value"><?= $encryptedFiles ?></div>
            <div class="stat-label">Encrypted Files</div>
        </div>
    </div>
    <div class="card stat-card">
        <div class="stat-icon" style="color: var(--warning);">??</div>
        <div class="stat-content">
            <div class="stat-value"><?= $totalSent ?></div>
            <div class="stat-label">Sent Shares</div>
        </div>
    </div>
    <div class="card stat-card">
        <div class="stat-icon" style="color: var(--success);">?</div>
        <div class="stat-content">
            <div class="stat-value"><?= $sentSuccess ?></div>
            <div class="stat-label">Successful Shares</div>
        </div>
    </div>
    <div class="card stat-card">
        <div class="stat-icon" style="color: var(--danger);">?</div>
        <div class="stat-content">
            <div class="stat-value"><?= $sentPending ?></div>
            <div class="stat-label">Pending Shares</div>
        </div>
    </div>
</div>

<h2 style="margin-bottom: 20px; font-size: 1.5rem;">Quick Actions</h2>
<div class="action-grid">
    <a href="/files.php" class="action-card">
        <div class="action-icon">??</div>
        <div>Upload File</div>
    </a>
    <a href="/shares.php" class="action-card">
        <div class="action-icon">??</div>
        <div>Encrypt & Share</div>
    </a>
    <a href="/sent-shares.php" class="action-card">
        <div class="action-icon">??</div>
        <div>View Sent Shares</div>
    </a>
    <a href="/received-shares.php" class="action-card">
        <div class="action-icon">??</div>
        <div>View Received</div>
    </a>
    <a href="/account.php" class="action-card">
        <div class="action-icon">??</div>
        <div>Account Settings</div>
    </a>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
