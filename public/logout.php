<?php
require_once __DIR__ . '/../config/config.php';

use Auth\AuthManager;

AuthManager::logout();
set_flash_message('info', 'You have been logged out.');
redirect('/login.php');
