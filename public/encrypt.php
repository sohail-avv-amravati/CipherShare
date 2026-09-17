<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;
use Files\FileManager;
use Crypto\ClassicalCiphers;
use Crypto\DocumentTextExtractor;
use Security\CSRF;

$user = AuthManager::requireLogin();
$userId = (int)$user['id'];
$error = null;
$classicalResult = null;
$sourceDocName = null;
$extractedCharCount = 0;

$fileId = isset($_GET['file_id']) ? (int)$_GET['file_id'] : 0;
$userFiles = FileManager::getUserFiles($userId);

// Handle downloading classical cipher output as a text file
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['download_classical_output'])) {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        $downloadText = $_POST['download_text'] ?? '';
        $docBase = preg_replace('/[^\w.\-]/', '_', $_POST['download_filename'] ?? 'cipher_output');
        $downloadFilename = pathinfo($docBase, PATHINFO_FILENAME) . '_classical.txt';

        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $downloadFilename . '"');
        header('Content-Length: ' . strlen($downloadText));
        header('Cache-Control: no-store, no-cache, must-revalidate');
        echo $downloadText;
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyToken($_POST['csrf_token'] ?? '')) {
        $error = "CSRF verification failed.";
    } else {
        $mode = $_POST['mode'] ?? 'aes';

        if ($mode === 'aes') {
            $targetFileId = (int)($_POST['file_id'] ?? 0);
            $passphrase = $_POST['passphrase'] ?? '';
            $confirmPassphrase = $_POST['confirm_passphrase'] ?? '';

            if (empty($passphrase) || mb_strlen($passphrase) < 6) {
                $error = "Passphrase must be at least 6 characters long.";
            } elseif ($passphrase !== $confirmPassphrase) {
                $error = "Passphrases do not match.";
            } else {
                if (FileManager::encryptUserFile($userId, $targetFileId, $passphrase, $error)) {
                    set_flash_message('success', 'File encrypted successfully with AES-256-GCM!');
                    redirect('/files.php');
                }
            }
        } elseif ($mode === 'classical') {
            $cipherAlg  = $_POST['classical_cipher']    ?? 'caesar';
            $operation  = $_POST['classical_operation'] ?? 'encrypt';
            $inputText  = trim($_POST['classical_input'] ?? '');
            $keyText    = $_POST['classical_key']       ?? '';
            $key2Text   = $_POST['classical_key2']      ?? 'KEY2';
            $shiftNum   = (int)($_POST['classical_shift'] ?? 3);

            // 1. Check if a document file was uploaded in this form (.txt, .doc, .docx, .pdf)
            if (isset($_FILES['classical_file']) && !empty($_FILES['classical_file']['name']) && $_FILES['classical_file']['error'] !== UPLOAD_ERR_NO_FILE) {
                $fileUploadError = null;
                $extracted = DocumentTextExtractor::extractFromUpload($_FILES['classical_file'], $fileUploadError);
                if ($fileUploadError) {
                    $error = $fileUploadError;
                } else {
                    $inputText = $extracted;
                    $sourceDocName = basename($_FILES['classical_file']['name']);
                    $extractedCharCount = mb_strlen($inputText, 'UTF-8');
                }
            }
            // 2. Check if an existing file from "My Files" was selected
            elseif (!empty($_POST['classical_existing_file_id'])) {
                $existingFileId = (int)$_POST['classical_existing_file_id'];
                $existingFile = FileManager::getUserFile($userId, $existingFileId);
                if ($existingFile && !$existingFile['is_encrypted']) {
                    $path = STORAGE_UPLOADS . '/' . $existingFile['stored_name'];
                    try {
                        $inputText = DocumentTextExtractor::extractFromFile($path, $existingFile['original_name']);
                        $sourceDocName = $existingFile['original_name'];
                        $extractedCharCount = mb_strlen($inputText, 'UTF-8');
                    } catch (\Exception $e) {
                        $error = "Could not extract text from selected file: " . $e->getMessage();
                    }
                } elseif ($existingFile && $existingFile['is_encrypted']) {
                    $error = "The selected file is encrypted with AES-256-GCM. Decrypt it first before running educational classical ciphers.";
                }
            }

            if (empty($error)) {
                if (empty($inputText)) {
                    $error = "Please enter text, upload a document (.txt, .doc, .docx, .pdf), or choose an existing file.";
                } else {
                    try {
                        if ($operation === 'decrypt') {
                            switch ($cipherAlg) {
                                case 'caesar':
                                    $classicalResult = ClassicalCiphers::caesarDecrypt($inputText, $shiftNum);
                                    break;
                                case 'substitution':
                                    $classicalResult = ClassicalCiphers::substitutionDecrypt($inputText, $keyText);
                                    break;
                                case 'affine':
                                    $classicalResult = ClassicalCiphers::affineDecrypt($inputText, $shiftNum, 5);
                                    break;
                                case 'vigenere':
                                    $classicalResult = ClassicalCiphers::vigenereDecrypt($inputText, $keyText);
                                    break;
                                case 'autokey':
                                    $classicalResult = ClassicalCiphers::autokeyDecrypt($inputText, $keyText);
                                    break;
                                case 'beaufort':
                                    $classicalResult = ClassicalCiphers::beaufortDecrypt($inputText, $keyText);
                                    break;
                                case 'playfair':
                                    $classicalResult = ClassicalCiphers::playfairDecrypt($inputText, $keyText);
                                    break;
                                case 'hill':
                                    $classicalResult = ClassicalCiphers::hillDecrypt($inputText, [[3,3],[2,5]]);
                                    break;
                                case 'railfence':
                                    $classicalResult = ClassicalCiphers::railFenceDecrypt($inputText, max(2, $shiftNum));
                                    break;
                                case 'columnar':
                                    $classicalResult = ClassicalCiphers::columnarDecrypt($inputText, $keyText ?: 'SECRET');
                                    break;
                                case 'double_columnar':
                                    $classicalResult = ClassicalCiphers::doubleTranspositionDecrypt($inputText, $keyText ?: 'KEY1', $key2Text ?: 'KEY2');
                                    break;
                                default:
                                    $error = "Unknown classical cipher algorithm.";
                            }
                        } else {
                            switch ($cipherAlg) {
                                case 'caesar':
                                    $classicalResult = ClassicalCiphers::caesarEncrypt($inputText, $shiftNum);
                                    break;
                                case 'substitution':
                                    $classicalResult = ClassicalCiphers::substitutionEncrypt($inputText, $keyText);
                                    break;
                                case 'affine':
                                    $classicalResult = ClassicalCiphers::affineEncrypt($inputText, $shiftNum, 5);
                                    break;
                                case 'vigenere':
                                    $classicalResult = ClassicalCiphers::vigenereEncrypt($inputText, $keyText);
                                    break;
                                case 'autokey':
                                    $classicalResult = ClassicalCiphers::autokeyEncrypt($inputText, $keyText);
                                    break;
                                case 'beaufort':
                                    $classicalResult = ClassicalCiphers::beaufortEncrypt($inputText, $keyText);
                                    break;
                                case 'playfair':
                                    $classicalResult = ClassicalCiphers::playfairEncrypt($inputText, $keyText);
                                    break;
                                case 'hill':
                                    $classicalResult = ClassicalCiphers::hillEncrypt($inputText, [[3,3],[2,5]]);
                                    break;
                                case 'railfence':
                                    $classicalResult = ClassicalCiphers::railFenceEncrypt($inputText, max(2, $shiftNum));
                                    break;
                                case 'columnar':
                                    $classicalResult = ClassicalCiphers::columnarEncrypt($inputText, $keyText ?: 'SECRET');
                                    break;
                                case 'double_columnar':
                                    $classicalResult = ClassicalCiphers::doubleTranspositionEncrypt($inputText, $keyText ?: 'KEY1', $key2Text ?: 'KEY2');
                                    break;
                                default:
                                    $error = "Unknown classical cipher algorithm.";
                            }
                        }
                    } catch (\Exception $e) {
                        $error = "Classical Cipher Error: " . $e->getMessage();
                    }
                }
            }
        }
    }
}

$pageTitle = "Encryption Engine";
include BASE_DIR . '/templates/header.php';
?>

<div style="max-width: 840px; margin: 0 auto;">
    <h1 style="font-size: 1.8rem; margin-bottom: 10px;">Encryption Engine</h1>
    <p style="color: var(--text-muted); margin-bottom: 30px;">
        Choose between production modern file protection (AES-256-GCM) or educational classical ciphers (with support for Text, Word, and PDF documents).
    </p>

    <?php if ($error): ?>
        <div class="alert alert-danger"><?= sanitize($error) ?></div>
    <?php endif; ?>

    <!-- Section 1: Modern File Encryption (AES-256-GCM) -->
    <div class="card" style="margin-bottom: 30px; border-color: var(--primary);">
        <h3 class="card-title" style="color: var(--primary);">
            🔐 Modern File Protection (AES-256-GCM)
        </h3>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 20px;">
            Securely encrypt an uploaded file at rest using authenticated AES-256-GCM with PBKDF2 key derivation.
        </p>

        <form action="/encrypt.php" method="POST">
            <?= CSRF::getFormField() ?>
            <input type="hidden" name="mode" value="aes">

            <div class="form-group">
                <label for="file_id">Select File to Encrypt</label>
                <select name="file_id" id="file_id" class="form-control" required>
                    <option value="">-- Choose File --</option>
                    <?php foreach ($userFiles as $f): ?>
                        <?php if (!$f['is_encrypted']): ?>
                            <option value="<?= $f['id'] ?>" <?= $f['id'] === $fileId ? 'selected' : '' ?>>
                                <?= sanitize($f['original_name']) ?> (<?= round($f['file_size']/1024, 1) ?> KB)
                            </option>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="passphrase">Encryption Passphrase</label>
                <input type="password" name="passphrase" id="passphrase" class="form-control" required placeholder="Strong passphrase" autocomplete="new-password">
            </div>

            <div class="form-group">
                <label for="confirm_passphrase">Confirm Encryption Passphrase</label>
                <input type="password" name="confirm_passphrase" id="confirm_passphrase" class="form-control" required autocomplete="new-password">
            </div>

            <button type="submit" class="btn btn-primary">Encrypt File with AES-256-GCM</button>
        </form>
    </div>

    <!-- Section 2: Educational Classical Ciphers with Document Upload -->
    <div class="card" style="border-color: var(--warning);">
        <h3 class="card-title" style="color: var(--warning);">
            📜 [EDUCATIONAL / CLASSICAL CIPHER] Demonstration Suite
        </h3>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 20px;">
            Demonstrate classical and historical ciphers on text or uploaded documents (<strong>.txt</strong>, <strong>.doc</strong>, <strong>.docx</strong>, <strong>.pdf</strong>). Classical ciphers are strictly for academic study and do NOT provide modern data security.
        </p>

        <?php
            $selCipher = $_POST['classical_cipher']    ?? 'caesar';
            $selOp     = $_POST['classical_operation'] ?? 'encrypt';
            $prevInput = $_POST['classical_input']     ?? '';
            $prevKey   = $_POST['classical_key']       ?? '';
            $prevKey2  = $_POST['classical_key2']      ?? '';
            $prevShift = (int)($_POST['classical_shift'] ?? 3);
        ?>
        <form action="/encrypt.php" method="POST" enctype="multipart/form-data">
            <?= CSRF::getFormField() ?>
            <input type="hidden" name="mode" value="classical">

            <!-- Operation Selection -->
            <div class="form-group">
                <label>Operation</label>
                <div style="display: flex; gap: 20px; align-items: center; padding: 10px 0;">
                    <label style="display: flex; align-items: center; gap: 8px; color: var(--text-main); cursor: pointer; font-weight: 500;">
                        <input type="radio" name="classical_operation" value="encrypt" <?= $selOp !== 'decrypt' ? 'checked' : '' ?>>
                        🔒 Encrypt (Encipher)
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; color: var(--text-main); cursor: pointer; font-weight: 500;">
                        <input type="radio" name="classical_operation" value="decrypt" <?= $selOp === 'decrypt' ? 'checked' : '' ?>>
                        🔓 Decrypt (Decipher)
                    </label>
                </div>
            </div>

            <!-- Cipher Selection -->
            <div class="form-group">
                <label for="classical_cipher">Select Classical Cipher</label>
                <select name="classical_cipher" id="classical_cipher" class="form-control">
                    <?php
                    $cipherOptions = [
                        'caesar'         => '[EDUCATIONAL] Caesar Cipher',
                        'substitution'   => '[EDUCATIONAL] Simple Substitution Cipher',
                        'affine'         => '[EDUCATIONAL] Affine Cipher',
                        'vigenere'       => '[EDUCATIONAL] Vigenère Cipher',
                        'autokey'        => '[EDUCATIONAL] Autokey Cipher',
                        'beaufort'       => '[EDUCATIONAL] Beaufort Cipher',
                        'playfair'       => '[EDUCATIONAL] Playfair Cipher',
                        'hill'           => '[EDUCATIONAL] Hill Cipher (2×2 Matrix)',
                        'railfence'      => '[EDUCATIONAL] Rail Fence Cipher',
                        'columnar'       => '[EDUCATIONAL] Columnar Transposition',
                        'double_columnar'=> '[EDUCATIONAL] Double Transposition',
                    ];
                    foreach ($cipherOptions as $val => $label): ?>
                        <option value="<?= $val ?>" <?= $selCipher === $val ? 'selected' : '' ?>>
                            <?= $label ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Input Option 1: File Upload (TXT / DOC / DOCX / PDF) -->
            <div style="background-color: #0F172A; padding: 16px; border-radius: var(--radius); border: 1px dashed var(--border-color); margin-bottom: 20px;">
                <div class="form-group" style="margin-bottom: 12px;">
                    <label for="classical_file" style="display: flex; align-items: center; gap: 6px;">
                        📄 <strong>Option A: Upload Document (.txt, .doc, .docx, .pdf)</strong>
                    </label>
                    <input type="file" name="classical_file" id="classical_file" class="form-control"
                           accept=".txt,.text,.doc,.docx,.pdf,.csv,.json,.md,.rtf">
                    <small style="color: var(--text-muted); display: block; margin-top: 4px;">
                        Upload any Text document, Word file (.doc, .docx), or PDF. The text will be extracted and processed through the cipher.
                    </small>
                </div>

                <!-- Input Option 2: Select from My Files -->
                <?php
                $eligibleFiles = array_filter($userFiles, function($f) {
                    return empty($f['is_encrypted']) && DocumentTextExtractor::isSupported($f['original_name']);
                });
                if (!empty($eligibleFiles)): ?>
                    <div class="form-group" style="margin-bottom: 0;">
                        <label for="classical_existing_file_id" style="font-size: 0.9rem; color: var(--text-muted);">
                            Or choose from your existing uploaded files in My Files:
                        </label>
                        <select name="classical_existing_file_id" id="classical_existing_file_id" class="form-control">
                            <option value="">-- Or select an uploaded document --</option>
                            <?php foreach ($eligibleFiles as $ef): ?>
                                <option value="<?= $ef['id'] ?>">
                                    📄 <?= sanitize($ef['original_name']) ?> (<?= format_file_size($ef['file_size']) ?>)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Input Option 3: Manual Text Input -->
            <div class="form-group">
                <label for="classical_input">
                    ✍️ <strong>Option B: Or Type / Paste Text Directly</strong>
                    <span style="font-weight: normal; color: var(--text-muted); font-size: 0.85rem;">(Used if no document is uploaded above)</span>
                </label>
                <textarea name="classical_input" id="classical_input" class="form-control" rows="4"
                    placeholder="<?= $selOp === 'decrypt' ? 'Type or paste ciphertext here...' : 'Type or paste plaintext here...' ?>"><?= sanitize($prevInput) ?></textarea>
            </div>

            <!-- Cipher Parameters -->
            <div class="form-group">
                <label for="classical_key">Key / Key Phrase / Substitution Alphabet</label>
                <input type="text" name="classical_key" id="classical_key" class="form-control"
                    value="<?= sanitize($prevKey) ?>"
                    placeholder="e.g. SECRETKEY, CIPHER, or 26-letter substitution alphabet">
                <small style="color: var(--text-muted);">For Substitution: enter 26 unique letters (e.g. QWERTYUIOPASDFGHJKLZXCVBNM).</small>
            </div>

            <?php if ($selCipher === 'double_columnar'): ?>
            <div class="form-group">
                <label for="classical_key2">Second Key (Double Transposition only)</label>
                <input type="text" name="classical_key2" id="classical_key2" class="form-control"
                    value="<?= sanitize($prevKey2) ?>"
                    placeholder="Second transposition key (e.g. KEY2)">
            </div>
            <?php else: ?>
                <input type="hidden" name="classical_key2" value="<?= sanitize($prevKey2) ?>">
            <?php endif; ?>

            <div class="form-group">
                <label for="classical_shift">Shift / Rails Number (for Caesar / Affine / Rail Fence)</label>
                <input type="number" name="classical_shift" id="classical_shift" class="form-control"
                    value="<?= $prevShift ?>" min="1" max="25">
            </div>

            <button type="submit" class="btn btn-secondary">
                <?= $selOp === 'decrypt' ? '🔓 Run Decipher on Document / Text' : '🔒 Run Cipher on Document / Text' ?>
            </button>
        </form>

        <?php if ($classicalResult !== null): ?>
            <!-- ═══════ CIPHER RESULT DISPLAY & DOWNLOAD ═══════ -->
            <div style="margin-top: 25px; background-color: #0F172A; padding: 20px; border-radius: var(--radius); border: 1px solid var(--warning);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                    <h4 style="color: var(--warning); margin: 0; font-size: 1.1rem;">
                        <?= $selOp === 'decrypt' ? '🔓 [EDUCATIONAL] DECIPHERED OUTPUT' : '🔒 [EDUCATIONAL] CIPHER OUTPUT' ?>
                    </h4>
                    <?php if ($sourceDocName): ?>
                        <span class="badge badge-success" style="font-size: 0.85rem;">
                            📄 Processed from: <?= sanitize($sourceDocName) ?> (<?= number_format($extractedCharCount) ?> chars)
                        </span>
                    <?php endif; ?>
                </div>

                <textarea class="form-control" rows="8" readonly style="font-family: monospace; font-size: 0.95rem; margin-bottom: 16px;"><?= sanitize($classicalResult) ?></textarea>

                <!-- Download Cipher Output as File Form -->
                <form action="/encrypt.php" method="POST" style="display: inline-block;">
                    <?= CSRF::getFormField() ?>
                    <input type="hidden" name="download_classical_output" value="1">
                    <input type="hidden" name="download_text" value="<?= sanitize($classicalResult) ?>">
                    <input type="hidden" name="download_filename" value="<?= sanitize($sourceDocName ? pathinfo($sourceDocName, PATHINFO_FILENAME) . '_' . $selOp : 'cipher_' . $selOp) ?>">
                    <button type="submit" class="btn btn-primary btn-sm">
                        📥 Download Output as Text File (.txt)
                    </button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php include BASE_DIR . '/templates/footer.php'; ?>
