<?php
require_once __DIR__ . '/../../config/config.php';

use Auth\AuthManager;
use Owner\OwnerManager;
use Database\Database;

$owner = AuthManager::requireOwner();
$stats = OwnerManager::getDashboardStats();

$db = Database::getInstance();
$stmtFiles = $db->query("
    SELECT f.id, f.original_name, f.mime_type, f.file_size, f.is_encrypted, f.cipher_alg, f.created_at, u.username
    FROM files f
    JOIN users u ON f.user_id = u.id
    ORDER BY f.created_at DESC
    LIMIT 100
");
$recentFiles = $stmtFiles->fetchAll(\PDO::FETCH_ASSOC);

$pageTitle = "File Statistics";
$isOwnerPage = true;
include BASE_DIR . '/templates/header.php';
?>

<div style="margin-bottom: 25px;">
    <h1 style="font-size: 1.8rem; color: var(--warning);">File Storage Statistics</h1>
    <p style="color: var(--text-muted);">Overview of stored files, MIME types, and encryption container distribution.</p>
</div>

<div class="card-grid">
    <div class="card">
        <div class="card-title">Total Files Stored</div>
        <div class="stat-number"><?= $stats['files']['total'] ?></div>
    </div>
    <div class="card">
        <div class="card-title">AES-256-GCM Encrypted Files</div>
        <div class="stat-number" style="color: var(--success);"><?= $stats['files']['encrypted'] ?></div>
    </div>
    <div class="card">
        <div class="card-title">Total Storage Consumption</div>
        <div class="stat-number"><?= $stats['files']['storage_formatted'] ?></div>
    </div>
</div>

<div class="card">
    <h3 class="card-title">Recent File Metadata (Content Inaccessible to Owner)</h3>
    <div class="table-responsive" style="margin-top: 15px;">
        <table>
            <thead>
                <tr>
                    <th>File ID</th>
                    <th>Owner Username</th>
                    <th>Filename</th>
                    <th>MIME Type</th>
                    <th>Size</th>
                    <th>Encryption</th>
                    <th>Uploaded At</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentFiles as $rf): ?>
                    <tr>
                        <td>#<?= $rf['id'] ?></td>
                        <td><?= sanitize($rf['username']) ?></td>
                        <td style="font-weight: 600;"><?= sanitize($rf['original_name']) ?></td>
                        <td><?= sanitize($rf['mime_type']) ?></td>
                        <td><?= round($rf['file_size']/1024, 1) ?> KB</td>
                        <td>
                            <?php if ($rf['is_encrypted']): ?>
                                <span class="badge badge-success">🔐 AES-256-GCM</span>
                            <?php else: ?>
                                <span class="badge badge-cancelled">Plaintext</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-size: 0.85rem; color: var(--text-muted);"><?= sanitize($rf['created_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
