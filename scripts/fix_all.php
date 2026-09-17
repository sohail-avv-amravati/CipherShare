<?php
// Fix all broken AuthManager::isLoggedIn() calls introduced by UI rewriter
$files = glob(__DIR__ . '/../public/*.php');
$files = array_merge($files, glob(__DIR__ . '/../public/owner/*.php'));
$files = array_merge($files, glob(__DIR__ . '/../templates/*.php'));

$fixed = 0;
foreach ($files as $path) {
    $content = file_get_contents($path);
    $new = str_replace(
        ['AuthManager::isLoggedIn()', 'AuthManager::isAuthenticated()'],
        ['AuthManager::getCurrentUser()', 'AuthManager::getCurrentUser()'],
        $content
    );
    if ($new !== $content) {
        file_put_contents($path, $new);
        echo "Fixed: " . basename($path) . "\n";
        $fixed++;
    }
}
echo "\nTotal files fixed: $fixed\n";
