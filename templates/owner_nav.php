<?php
use Auth\AuthManager;
$currentUser = AuthManager::getCurrentUser();
?>
<nav class="nav-bar">
    <a href="/owner/dashboard.php" class="brand" style="color: var(--warning);">
        <span class="brand-icon">👑</span> CipherShare Owner Portal
    </a>
    <input type="checkbox" id="owner-nav-toggle" class="nav-toggle">
    <label for="owner-nav-toggle" class="nav-toggle-label">&#9776;</label>

    <ul class="nav-links">
        <li><a href="/owner/dashboard.php">Dashboard</a></li>
        <li><a href="/owner/users.php">Users</a></li>
        <li><a href="/owner/files.php">Files Stats</a></li>
        <li><a href="/owner/shares.php">Shares Stats</a></li>
        <li><a href="/owner/security.php">Security</a></li>
        <li><a href="/owner/audit.php">Audit Logs</a></li>
        <li><a href="/dashboard.php" style="color: var(--primary);">User Area</a></li>
        <li><a href="/logout.php">Logout</a></li>
    </ul>
</nav>
