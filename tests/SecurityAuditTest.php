<?php
// Security Audit Verification Test

$projectDir = BASE_DIR;

// 1. Scan for any .js files
$jsFiles = [];
$dirIter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($projectDir));
foreach ($dirIter as $file) {
    if ($file->isFile()) {
        if ($file->getExtension() === 'js') {
            $jsFiles[] = $file->getPathname();
        }
    }
}
assertTest(count($jsFiles) === 0, "Security Audit: ABSOLUTELY ZERO .js files exist in codebase");

// 2. Scan all PHP/HTML/CSS files for forbidden JS/REST/AI technologies
$forbiddenPatterns = [
    '/<script/i' => 'Inline or external script tag',
    '/window\.fetch/i' => 'JavaScript fetch API',
    '/XMLHttpRequest/i' => 'AJAX XMLHttpRequest',
    '/jQuery/i' => 'jQuery library',
    '/express/i' => 'Node.js Express framework',
    '/flask/i' => 'Python Flask framework',
    '/django/i' => 'Python Django framework',
    '/fastapi/i' => 'Python FastAPI framework',
    '/\/api\//i' => 'REST API endpoint (/api/)',
    '/openai/i' => 'OpenAI API service',
    '/chatgpt/i' => 'ChatGPT API service',
    '/gemini/i' => 'Gemini AI service',
    '/brevo/i' => 'Brevo email service',
    '/smtp/i' => 'SMTP email protocol',
    '/otp/i' => 'OTP authentication service'
];

$foundViolations = [];
foreach ($dirIter as $file) {
    if ($file->isFile() && in_array($file->getExtension(), ['php', 'html', 'css', 'sql'])) {
        if (strpos($file->getPathname(), 'SecurityAuditTest.php') !== false) {
            continue;
        }

        $content = file_get_contents($file->getPathname());
        foreach ($forbiddenPatterns as $pattern => $description) {
            if (preg_match($pattern, $content)) {
                $foundViolations[] = "File {$file->getFilename()} violates rule: {$description}";
            }
        }
    }
}

assertTest(count($foundViolations) === 0, "Security Audit: Zero forbidden technologies/services (JS/REST/AI/Email/Flask/Node/OTP)");

if (!empty($foundViolations)) {
    echo "  Violations details:\n";
    foreach ($foundViolations as $v) {
        echo "   - {$v}\n";
    }
}
