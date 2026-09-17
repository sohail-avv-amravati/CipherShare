<?php
require_once __DIR__ . '/../config/config.php';
$db = \Database\Database::getInstance();

// Keep only OWNER (role=OWNER) — delete all USER accounts and their data
$users = $db->query("SELECT id, username FROM users WHERE role = 'USER'")->fetchAll(PDO::FETCH_ASSOC);

foreach ($users as $u) {
    $id = $u['id'];
    // Delete shares where user is sender or recipient
    $db->prepare("DELETE FROM shares WHERE sender_id = ? OR recipient_id = ?")->execute([$id, $id]);
    // Delete files
    $db->prepare("DELETE FROM files WHERE user_id = ?")->execute([$id]);
    // Delete security question assignments
    $db->prepare("DELETE FROM user_security_questions WHERE user_id = ?")->execute([$id]);
    // Delete user
    $db->prepare("DELETE FROM users WHERE id = ?")->execute([$id]);
    echo "Deleted user: " . $u['username'] . " (ID $id)\n";
}

// Clear all audit logs
$db->exec("DELETE FROM audit_logs");
echo "Audit log cleared.\n";

// Show remaining users
echo "\nRemaining users:\n";
foreach ($db->query("SELECT id, username, role FROM users")->fetchAll(PDO::FETCH_ASSOC) as $r) {
    echo "  #" . $r['id'] . " " . $r['username'] . " [" . $r['role'] . "]\n";
}
echo "\nDone.\n";
