<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Shares\ShareManager;

$user   = AuthManager::requireLogin();
$userId = (int)$user['id'];

// Get quick stats
$userFiles      = FileManager::getUserFiles($userId);
$sentShares     = ShareManager::getSentShares($userId);
$receivedShares = ShareManager::getReceivedShares($userId);

$totalFiles     = count($userFiles);
$encryptedFiles = count(array_filter($userFiles, fn($f) => $f['is_encrypted']));

$totalSent   = count($sentShares);
$sentSuccess = count(array_filter($sentShares, fn($s) => $s['status'] === 'SUCCESS'));
$sentPending = count(array_filter($sentShares, fn($s) => $s['status'] === 'PENDING'));

$pageTitle = "Dashboard";
include BASE_DIR . '/templates/header.php';
?>

<div style="margin-bottom: 16px;">
    <h1 style="font-size: 1.6rem; color: var(--text-main); margin-bottom: 2px;">Welcome back, <?= sanitize($user['username']) ?> 👋</h1>
    <p style="color: var(--text-muted); font-size: 0.88rem;"><?= date('l, F j, Y') ?></p>
</div>

<!-- Stats Grid -->
<div class="card-grid" style="margin-bottom: 20px;">
    <div class="card" style="display: flex; align-items: center; gap: 14px; padding: 14px 16px;">
        <div style="font-size: 2rem; color: var(--primary);">📁</div>
        <div>
            <div class="stat-number" style="font-size: 1.8rem;"><?= $totalFiles ?></div>
            <div class="stat-desc">Total Files</div>
        </div>
    </div>
    <div class="card" style="display: flex; align-items: center; gap: 14px; padding: 14px 16px;">
        <div style="font-size: 2rem; color: var(--success);">🔐</div>
        <div>
            <div class="stat-number" style="font-size: 1.8rem; color: var(--success);"><?= $encryptedFiles ?></div>
            <div class="stat-desc">Encrypted Files</div>
        </div>
    </div>
    <div class="card" style="display: flex; align-items: center; gap: 14px; padding: 14px 16px;">
        <div style="font-size: 2rem; color: var(--warning);">📤</div>
        <div>
            <div class="stat-number" style="font-size: 1.8rem; color: var(--warning);"><?= $totalSent ?></div>
            <div class="stat-desc">Sent Shares</div>
        </div>
    </div>
    <div class="card" style="display: flex; align-items: center; gap: 14px; padding: 14px 16px;">
        <div style="font-size: 2rem; color: var(--success);">✅</div>
        <div>
            <div class="stat-number" style="font-size: 1.8rem; color: var(--success);"><?= $sentSuccess ?></div>
            <div class="stat-desc">Successful Shares</div>
        </div>
    </div>
    <div class="card" style="display: flex; align-items: center; gap: 14px; padding: 14px 16px;">
        <div style="font-size: 2rem; color: var(--danger);">⏳</div>
        <div>
            <div class="stat-number" style="font-size: 1.8rem; color: var(--warning);"><?= $sentPending ?></div>
            <div class="stat-desc">Pending Shares</div>
        </div>
    </div>
</div>

<!-- Quick Actions -->
<h2 style="margin-bottom: 12px; font-size: 1.1rem; color: var(--text-main);">Quick Actions</h2>
<div class="action-grid">
    <a href="/files.php" class="action-card">
        <div class="action-icon">📁</div>
        <div>My Files</div>
    </a>
    <a href="/encrypt.php" class="action-card">
        <div class="action-icon">🔐</div>
        <div>Encrypt File</div>
    </a>
    <a href="/decrypt.php" class="action-card">
        <div class="action-icon">🔓</div>
        <div>Decrypt File</div>
    </a>
    <a href="/shares.php" class="action-card">
        <div class="action-icon">📤</div>
        <div>Share File</div>
    </a>
    <a href="/sent-shares.php" class="action-card">
        <div class="action-icon">📨</div>
        <div>Sent Shares</div>
    </a>
    <a href="/received-shares.php" class="action-card">
        <div class="action-icon">📥</div>
        <div>Received Shares</div>
    </a>
    <a href="/account.php" class="action-card">
        <div class="action-icon">👤</div>
        <div>Account</div>
    </a>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
