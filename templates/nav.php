<?php
use Auth\AuthManager;
$currentUser = AuthManager::getCurrentUser();
?>
<div class="owner-nav-bar" style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap;">
    <a href="/owner/dashboard.php" style="font-weight: 600;">📊 Dashboard</a>
    <a href="/owner/users.php" style="font-weight: 600;">👥 Users</a>
    <a href="/owner/audit.php" style="font-weight: 600;">📋 Audit Trail</a>
    <a href="/owner/security.php" style="font-weight: 600;">⚙️ Security</a>
    <a href="/dashboard.php" style="color: var(--primary); font-size: 0.9rem; margin-left: 10px;">🏠 User View</a>
    <a href="/logout.php" style="color: var(--danger); font-size: 0.9rem; margin-left: 10px;">Logout</a>
</div>
