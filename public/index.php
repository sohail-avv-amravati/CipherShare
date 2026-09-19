<?php
require_once __DIR__ . '/../config/config.php';
use Auth\AuthManager;

if (AuthManager::getCurrentUser()) {
    redirect('/dashboard.php');
}

$pageTitle = "CipherShare - Secure File Sharing";
include BASE_DIR . '/templates/header.php';
?>

<div style="text-align: center; padding: 10px 0; max-width: 1000px; margin: 0 auto;">
    <h1 style="font-size: 2.5rem; font-weight: 800; margin-bottom: 10px; line-height: 1.2;">
        Secure File Sharing<br><span style="color: var(--primary);">Zero-Trust & Encrypted</span>
    </h1>
    <p style="font-size: 1rem; color: var(--text-muted); max-width: 580px; margin: 0 auto 20px auto;">
        Encrypt your sensitive files using AES-256-GCM and share them with server-enforced expiration limits. Fast, reliable, and private.
    </p>
    <div style="display: flex; gap: 12px; justify-content: center; margin-bottom: 28px; flex-wrap: wrap;">
        <a href="/register.php" class="btn btn-primary btn-inline" style="font-size: 0.95rem; padding: 10px 28px;">Create Account</a>
        <a href="/login.php" class="btn btn-secondary btn-inline" style="font-size: 0.95rem; padding: 10px 28px;">Log In</a>
    </div>
    
    <div class="card-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); text-align: left; gap: 12px;">
        <div class="card" style="padding: 14px 16px;">
            <div style="font-size: 1.8rem; margin-bottom: 6px;">🔐</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1rem; margin-bottom: 4px;">AES-256-GCM Encryption</h3>
            <p style="color: var(--text-muted); font-size: 0.83rem;">Authenticated symmetric container encryption protecting files at rest.</p>
        </div>
        <div class="card" style="padding: 14px 16px;">
            <div style="font-size: 1.8rem; margin-bottom: 6px;">⏳</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1rem; margin-bottom: 4px;">Auto-Expiring Shares</h3>
            <p style="color: var(--text-muted); font-size: 0.83rem;">Set expiration deadlines on shared files so access revokes on schedule.</p>
        </div>
        <div class="card" style="padding: 14px 16px;">
            <div style="font-size: 1.8rem; margin-bottom: 6px;">🛡️</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1rem; margin-bottom: 4px;">Zero-Email Security</h3>
            <p style="color: var(--text-muted); font-size: 0.83rem;">Assigned security questions pool for password recovery without email.</p>
        </div>
        <div class="card" style="padding: 14px 16px;">
            <div style="font-size: 1.8rem; margin-bottom: 6px;">📊</div>
            <h3 class="card-title" style="color: var(--text-main); text-transform: none; font-size: 1rem; margin-bottom: 4px;">Access Tracking & Logs</h3>
            <p style="color: var(--text-muted); font-size: 0.83rem;">Monitor real-time download and recipient access logs securely.</p>
        </div>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
