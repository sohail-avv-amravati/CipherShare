<?php
namespace Database;

use PDO;
use PDOException;

class Database {
    private static ?PDO $instance = null;

    public static function getInstance(): PDO {
        if (self::$instance === null) {
            $dbPath = DB_PATH;
            $dir = dirname($dbPath);
            if (!file_exists($dir)) {
                @mkdir($dir, 0777, true);
            }
            try {
                self::$instance = new PDO("sqlite:" . $dbPath);
                self::$instance->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                self::$instance->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                self::$instance->exec("PRAGMA foreign_keys = ON;");
                self::$instance->exec("PRAGMA journal_mode = WAL;");

                // Auto-create database schema if tables are missing
                $tables = self::$instance->query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")->fetch();
                if (!$tables) {
                    $schemaFile = BASE_DIR . '/database/schema.sql';
                    if (file_exists($schemaFile)) {
                        self::$instance->exec(file_get_contents($schemaFile));
                    }
                }
            } catch (PDOException $e) {
                die("Database Connection Error: " . $e->getMessage());
            }
        }
        return self::$instance;
    }
}