<?php
$f = file_get_contents(__DIR__ . '/../public/index.php');
$f = str_replace('AuthManager::isLoggedIn()', 'AuthManager::getCurrentUser()', $f);
// Fix garbled emojis in feature cards
$f = str_replace('<div style="font-size: 2rem; margin-bottom: 15px;">??</div>', '<div style="font-size: 2rem; margin-bottom: 15px;">&#x1F512;</div>', $f);
$f = str_replace('<div style="font-size: 2rem; margin-bottom: 15px;">??</div>', '<div style="font-size: 2rem; margin-bottom: 15px;">&#x23F3;</div>', $f);
$f = str_replace('<div style="font-size: 2rem; margin-bottom: 15px;">???</div>', '<div style="font-size: 2rem; margin-bottom: 15px;">&#x1F6E1;&#xFE0F;</div>', $f);
file_put_contents(__DIR__ . '/../public/index.php', $f);
echo "Fixed.\n";
