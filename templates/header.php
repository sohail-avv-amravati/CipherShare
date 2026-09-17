<?php
require_once __DIR__ . '/../config/config.php';
use Security\CSRF;
use Auth\AuthManager;

$flash       = get_flash_message();
$pageTitle   = $pageTitle ?? APP_NAME;
$currentUser = AuthManager::getCurrentUser();
$uri         = $_SERVER['REQUEST_URI'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= sanitize($pageTitle) ?> | CipherShare</title>
  <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
<?php if ($currentUser && !(isset($isOwnerPage) && $isOwnerPage)): ?>
<input type="checkbox" id="sidebar-toggle" class="sidebar-toggle-input">
<div class="app-layout">
  <label for="sidebar-toggle" class="sidebar-overlay-label"></label>
  <aside class="sidebar">
    <a href="/dashboard.php" class="sidebar-brand">🛡️ CipherShare</a>
    <nav class="sidebar-nav">
      <a href="/dashboard.php" class="<?= strpos($uri,'/dashboard')!==false?'active':'' ?>">🏠 Dashboard</a>
      <a href="/files.php" class="<?= strpos($uri,'/files')!==false?'active':'' ?>">📁 My Files</a>
      <a href="/encrypt.php" class="<?= strpos($uri,'/encrypt')!==false?'active':'' ?>">🔐 Encrypt</a>
      <a href="/decrypt.php" class="<?= (strpos($uri,'/decrypt')!==false && strpos($uri,'/received')===false)?'active':'' ?>">🔓 Decrypt</a>
      <a href="/shares.php" class="<?= ($uri==='/shares.php'||strpos($uri,'/shares.php?')!==false)?'active':'' ?>">📤 Share File</a>
      <a href="/sent-shares.php" class="<?= strpos($uri,'/sent-shares')!==false?'active':'' ?>">📨 Sent Shares</a>
      <a href="/received-shares.php" class="<?= strpos($uri,'/received-shares')!==false?'active':'' ?>">📥 Received Shares</a>
      <a href="/account.php" class="<?= strpos($uri,'/account')!==false?'active':'' ?>">👤 Account</a>
      <?php if ($currentUser['role'] === 'OWNER'): ?>
        <a href="/owner/dashboard.php" style="color: var(--warning); border-top: 1px solid var(--border-color); margin-top: 10px; padding-top: 12px;">👑 Owner Portal</a>
      <?php endif; ?>
    </nav>
    <div class="sidebar-footer">
      <div class="sidebar-user-name">👤 <?= sanitize($currentUser['username']) ?></div>
      <a href="/logout.php" class="btn btn-secondary btn-sm" style="margin-top: 6px; width: 100%; text-align: center;">Logout</a>
    </div>
  </aside>
  <div class="main-content">
    <div class="topbar">
      <label for="sidebar-toggle" class="hamburger-btn">☰</label>
      <h1 class="topbar-title"><?= sanitize($pageTitle) ?></h1>
    </div>
    <div class="content-area">
      <?php if ($flash): ?>
        <div class="alert alert-<?= sanitize($flash['type']) ?>">
          <?= sanitize($flash['message']) ?>
        </div>
      <?php endif; ?>
<?php else: ?>
  <header class="public-header">
    <div class="container public-nav-container">
      <a href="/index.php" class="brand">🛡️ CipherShare</a>
      <div class="public-nav-links">
        <?php if (isset($isOwnerPage) && $isOwnerPage): ?>
          <?php include __DIR__ . '/nav.php'; ?>
        <?php else: ?>
          <?php if ($currentUser): ?>
            <a href="/dashboard.php" class="btn btn-primary btn-sm">Dashboard</a>
            <?php if ($currentUser['role'] === 'OWNER'): ?>
              <a href="/owner/dashboard.php" class="btn btn-warning btn-sm" style="color:#000;">Owner Portal</a>
            <?php endif; ?>
            <a href="/logout.php" class="btn btn-secondary btn-sm">Logout</a>
          <?php else: ?>
            <a href="/login.php" class="btn btn-secondary btn-sm">Login</a>
            <a href="/register.php" class="btn btn-primary btn-sm">Register</a>
            <a href="/owner/login.php" style="color: var(--warning); font-size: 0.9rem; margin-left: 8px;">Owner Login</a>
          <?php endif; ?>
        <?php endif; ?>
      </div>
    </div>
  </header>
  <main class="public-main">
    <div class="container">
      <?php if ($flash): ?>
        <div class="alert alert-<?= sanitize($flash['type']) ?>">
          <?= sanitize($flash['message']) ?>
        </div>
      <?php endif; ?>
<?php endif; ?>
