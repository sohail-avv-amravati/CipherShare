<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Owner\OwnerManager;
use Database\Database;

$owner = AuthManager::requireOwner();

// Get target user
$targetId = (int)($_GET['user_id'] ?? 0);
if ($targetId <= 0) {
    redirect('/owner/users.php');
}

$db = Database::getInstance();

// Load target user info
$stmt = $db->prepare("SELECT id, username, role, status, created_at, last_login_at FROM users WHERE id = :id AND role = 'USER'");
$stmt->execute([':id' => $targetId]);
$targetUser = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$targetUser) {
    set_flash_message('danger', 'User not found.');
    redirect('/owner/users.php');
}

// Pagination
$page    = max(1, (int)($_GET['page'] ?? 1));
$perPage = 20;
$offset  = ($page - 1) * $perPage;

// Category filter
$catFilter = $_GET['category'] ?? 'ALL';

// Count total
$countSql = "SELECT COUNT(*) FROM audit_logs WHERE actor_username = :u";
$countParams = [':u' => $targetUser['username']];
if ($catFilter !== 'ALL') {
    $countSql .= " AND event_category = :cat";
    $countParams[':cat'] = $catFilter;
}
$countStmt = $db->prepare($countSql);
$countStmt->execute($countParams);
$totalItems = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($totalItems / $perPage));

// Fetch logs
$logSql = "SELECT * FROM audit_logs WHERE actor_username = :u";
$logParams = [':u' => $targetUser['username']];
if ($catFilter !== 'ALL') {
    $logSql .= " AND event_category = :cat";
    $logParams[':cat'] = $catFilter;
}
$logSql .= " ORDER BY created_at DESC LIMIT :lim OFFSET :off";
$logStmt = $db->prepare($logSql);
foreach ($logParams as $k => $v) { $logStmt->bindValue($k, $v); }
$logStmt->bindValue(':lim', $perPage, PDO::PARAM_INT);
$logStmt->bindValue(':off', $offset, PDO::PARAM_INT);
$logStmt->execute();
$logs = $logStmt->fetchAll(PDO::FETCH_ASSOC);

// User stats
$fcStmt = $db->prepare("SELECT COUNT(*) FROM files WHERE user_id = :id");
$fcStmt->execute([':id' => $targetId]);
$fileCount = (int)$fcStmt->fetchColumn();

$shareStmt = $db->prepare("SELECT COUNT(*) FROM shares WHERE sender_id = :id");
$shareStmt->execute([':id' => $targetId]);
$shareCount = (int)$shareStmt->fetchColumn();

$loginStmt = $db->prepare("SELECT COUNT(*) FROM audit_logs WHERE actor_username = :u AND event_type = 'LOGIN'");
$loginStmt->execute([':u' => $targetUser['username']]);
$loginCount = (int)$loginStmt->fetchColumn();

$failStmt = $db->prepare("SELECT COUNT(*) FROM audit_logs WHERE actor_username = :u AND event_type = 'LOGIN_FAILED'");
$failStmt->execute([':u' => $targetUser['username']]);
$failedLogins = (int)$failStmt->fetchColumn();

function ua_pagination_url(int $p, int $uid, string $cat): string {
    return '/owner/user-activity.php?user_id=' . $uid . '&page=' . $p . '&category=' . urlencode($cat);
}

$catColors = [
    'AUTH'     => 'badge-auth',
    'FILE'     => 'badge-file',
    'SHARE'    => 'badge-share',
    'OWNER'    => 'badge-owner',
    'SECURITY' => 'badge-security',
];

$pageTitle = "Activity: " . $targetUser['username'];
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div style="margin-bottom:20px;">
    <a href="/owner/users.php" style="color:var(--text-muted);font-size:0.9rem;">&larr; Back to User Management</a>
</div>

<!-- User Profile Header -->
<div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:12px;padding:24px 28px;margin-bottom:24px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;">
    <div style="width:60px;height:60px;border-radius:50%;background:linear-gradient(135deg,#6366F1,#8B5CF6);display:flex;align-items:center;justify-content:center;font-size:1.6rem;font-weight:800;color:#fff;flex-shrink:0;">
        <?= strtoupper(mb_substr($targetUser['username'], 0, 1)) ?>
    </div>
    <div style="flex:1;min-width:200px;">
        <h1 style="font-size:1.5rem;font-weight:700;color:var(--text-main);margin-bottom:4px;"><?= sanitize($targetUser['username']) ?></h1>
        <div style="font-size:0.85rem;color:var(--text-muted);">
            Registered: <?= date('d M Y', strtotime($targetUser['created_at'])) ?>
            &nbsp;&bull;&nbsp;
            Last Login: <?= $targetUser['last_login_at'] ? date('d M Y, h:i A', strtotime($targetUser['last_login_at'])) : 'Never' ?>
            &nbsp;&bull;&nbsp;
            <?php if ($targetUser['status'] === 'ACTIVE'): ?>
                <span class="badge badge-active">ACTIVE</span>
            <?php elseif ($targetUser['status'] === 'SUSPENDED'): ?>
                <span class="badge badge-suspended">SUSPENDED</span>
            <?php else: ?>
                <span class="badge badge-deactivated">DEACTIVATED</span>
            <?php endif; ?>
        </div>
    </div>
    <a href="/owner/users.php?action=confirm_suspend&user_id=<?= $targetUser['id'] ?>" class="btn btn-danger btn-sm" style="width:auto;">Manage Account</a>
</div>

<!-- Quick Stats -->
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:28px;">
    <div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:16px 20px;">
        <div style="font-size:1.8rem;font-weight:800;color:#6366F1;"><?= $loginCount ?></div>
        <div style="font-size:0.8rem;color:var(--text-muted);margin-top:2px;">Total Logins</div>
    </div>
    <div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:16px 20px;">
        <div style="font-size:1.8rem;font-weight:800;color:<?= $failedLogins > 3 ? '#EF4444' : '#F59E0B' ?>;"><?= $failedLogins ?></div>
        <div style="font-size:0.8rem;color:var(--text-muted);margin-top:2px;">Failed Logins</div>
    </div>
    <div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:16px 20px;">
        <div style="font-size:1.8rem;font-weight:800;color:#10B981;"><?= $fileCount ?></div>
        <div style="font-size:0.8rem;color:var(--text-muted);margin-top:2px;">Files Stored</div>
    </div>
    <div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:16px 20px;">
        <div style="font-size:1.8rem;font-weight:800;color:#8B5CF6;"><?= $shareCount ?></div>
        <div style="font-size:0.8rem;color:var(--text-muted);margin-top:2px;">Shares Sent</div>
    </div>
    <div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:16px 20px;">
        <div style="font-size:1.8rem;font-weight:800;color:var(--text-main);"><?= $totalItems ?></div>
        <div style="font-size:0.8rem;color:var(--text-muted);margin-top:2px;">Total Log Entries</div>
    </div>
</div>

<!-- Category Filter Tabs -->
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px;">
    <?php foreach (['ALL' => 'All Events', 'AUTH' => 'Auth', 'FILE' => 'Files', 'SHARE' => 'Shares', 'SECURITY' => 'Security'] as $cat => $label): ?>
        <a href="<?= ua_pagination_url(1, $targetUser['id'], $cat) ?>"
           style="padding:7px 16px;border-radius:20px;font-size:0.85rem;font-weight:600;text-decoration:none;border:1px solid;
                  <?= $catFilter === $cat
                        ? 'background:#6366F1;border-color:#6366F1;color:#fff;'
                        : 'background:var(--card-bg);border-color:var(--border-color);color:var(--text-muted);' ?>">
            <?= $label ?>
        </a>
    <?php endforeach; ?>
</div>

<!-- Activity Log -->
<?php if (empty($logs)): ?>
    <div class="empty-state">
        <div class="empty-state-icon">📋</div>
        <div class="empty-state-text">No activity recorded yet for <?= sanitize($targetUser['username']) ?>.</div>
        <div class="empty-state-sub">Activity will appear here as they use CipherShare.</div>
    </div>
<?php else: ?>

    <div style="font-size:0.83rem;color:var(--text-muted);margin-bottom:12px;">
        Showing <?= count($logs) ?> of <?= $totalItems ?> total events
        (Page <?= $currentPage = $page ?> of <?= $totalPages ?>)
    </div>

    <div style="display:flex;flex-direction:column;gap:10px;">
        <?php foreach ($logs as $log):
            $cat   = $log['event_category'] ?? 'AUTH';
            $bCls  = $catColors[$cat] ?? 'badge-auth';
            $target = '';
            if (!empty($log['target_user_id']))  $target = 'User ID #' . (int)$log['target_user_id'];
            elseif (!empty($log['target_file_id'])) $target = 'File ID #' . (int)$log['target_file_id'];
            elseif (!empty($log['target_share_id']))  $target = 'Share ID #' . (int)$log['target_share_id'];
        ?>
        <div style="background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:14px 18px;display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;">
            <div style="flex:0 0 auto;width:42px;height:42px;border-radius:8px;background:rgba(99,102,241,0.12);display:flex;align-items:center;justify-content:center;font-size:1.2rem;">
                <?php
                $icons = ['LOGIN'=>'🔑','LOGIN_FAILED'=>'🚫','LOGOUT'=>'👋','UPLOAD'=>'📤','DOWNLOAD'=>'📥',
                          'ENCRYPT'=>'🔐','DECRYPT'=>'🔓','SHARE_CREATE'=>'📨','SHARE_ACCESS'=>'📬',
                          'PASSWORD_RESET'=>'🔄','REGISTER'=>'✅','DELETE'=>'🗑️'];
                echo $icons[$log['event_type']] ?? '📋';
                ?>
            </div>
            <div style="flex:1;min-width:200px;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap;">
                    <strong style="font-size:0.95rem;"><?= sanitize($log['event_type']) ?></strong>
                    <span class="badge <?= $bCls ?>"><?= sanitize($cat) ?></span>
                    <?php if ($target): ?>
                        <span style="font-size:0.8rem;color:var(--text-muted);"><?= $target ?></span>
                    <?php endif; ?>
                </div>
                <?php if (!empty($log['description'])): ?>
                <div style="font-size:0.88rem;color:var(--text-muted);"><?= sanitize($log['description']) ?></div>
                <?php endif; ?>
            </div>
            <div style="flex:0 0 auto;text-align:right;font-size:0.78rem;color:var(--text-muted);white-space:nowrap;">
                <?= date('d M Y', strtotime($log['created_at'])) ?><br>
                <strong style="color:var(--text-main);"><?= date('h:i A', strtotime($log['created_at'])) ?></strong><br>
                <span style="font-family:monospace;font-size:0.72rem;"><?= sanitize($log['ip_address'] ?? '127.0.0.1') ?></span>
            </div>
        </div>
        <?php endforeach; ?>
    </div>

    <!-- Pagination -->
    <?php if ($totalPages > 1): ?>
    <div class="pagination" style="margin-top:24px;">
        <?php if ($page > 1): ?>
            <a href="<?= ua_pagination_url($page - 1, $targetUser['id'], $catFilter) ?>">&laquo; Prev</a>
        <?php else: ?>
            <span class="disabled">&laquo; Prev</span>
        <?php endif; ?>
        <?php for ($p = max(1, $page - 2); $p <= min($totalPages, $page + 2); $p++): ?>
            <?php if ($p === $page): ?>
                <span class="active"><?= $p ?></span>
            <?php else: ?>
                <a href="<?= ua_pagination_url($p, $targetUser['id'], $catFilter) ?>"><?= $p ?></a>
            <?php endif; ?>
        <?php endfor; ?>
        <?php if ($page < $totalPages): ?>
            <a href="<?= ua_pagination_url($page + 1, $targetUser['id'], $catFilter) ?>">Next &raquo;</a>
        <?php else: ?>
            <span class="disabled">Next &raquo;</span>
        <?php endif; ?>
    </div>
    <?php endif; ?>

<?php endif; ?>

<?php include BASE_DIR . '/templates/footer.php'; ?>
