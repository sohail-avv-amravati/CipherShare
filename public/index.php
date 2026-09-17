<?php
require_once __DIR__ . '/../config/config.php';
use Auth\AuthManager;

if (AuthManager::getCurrentUser()) {
    redirect('/dashboard.php');
}

$pageTitle = "CipherShare - Secure File Sharing";
include BASE_DIR . '/templates/header.php';
?>

<div style="text-align: center; padding: 60px 20px;">
    <h1 style="font-size: 3.2rem; font-weight: 800; margin-bottom: 20px; line-height: 1.2;">
        Secure File Sharing<br><span style="color: var(--primary);">Zero-Trust & Encrypted</span>
    </h1>
    <p style="font-size: 1.15rem; color: var(--text-muted); max-width: 640px; margin: 0 auto 36px auto;">
        Encrypt your sensitive files using AES-256-GCM and share them with server-enforced expiration limits. Fast, reliable, and private.
    </p>
    <div style="display: flex; gap: 16px; justify-content: center; margin-bottom: 60px; flex-wrap: wrap;">
        <a href="/register.php" class="btn btn-primary btn-inline" style="font-size: 1.05rem; padding: 12px 32px;">Create Account</a>
        <a href="/login.php" class="btn btn-secondary btn-inline" style="font-size: 1.05rem; padding: 12px 32px;">Log In</a>
    </div>
    
    <div class="card-grid" style="max-width: 1000px; margin: 0 auto; text-align: left;">
        <div class="card">
            <div style="font-size: 2.2rem; margin-bottom: 12px;">🔐</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1.15rem;">AES-256-GCM Encryption</h3>
            <p style="color: var(--text-muted); font-size: 0.95rem;">Authenticated symmetric encryption container protecting your files at rest.</p>
        </div>
        <div class="card">
            <div style="font-size: 2.2rem; margin-bottom: 12px;">⏳</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1.15rem;">Auto-Expiring Shares</h3>
            <p style="color: var(--text-muted); font-size: 0.95rem;">Set expiration times on shared files so access automatically revokes on schedule.</p>
        </div>
        <div class="card">
            <div style="font-size: 2.2rem; margin-bottom: 12px;">🛡️</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1.15rem;">Zero-Email Security</h3>
            <p style="color: var(--text-muted); font-size: 0.95rem;">Assigned security questions pool for account protection without external email dependencies.</p>
        </div>
        <div class="card">
            <div style="font-size: 2.2rem; margin-bottom: 12px;">📊</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1.15rem;">Access Tracking & Logs</h3>
            <p style="color: var(--text-muted); font-size: 0.95rem;">Monitor real-time download and recipient access logs securely.</p>
        </div>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
