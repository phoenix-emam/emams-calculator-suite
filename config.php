<?php
// Database configuration
define('DB_HOST', 'sql307.infinityfree.com');
define('DB_NAME', 'if0_39773868_emam_calc');
define('DB_USER', 'if0_39773868');
define('DB_PASS', 'EjJyJ4KbAG'); // Add your password here

// Application configuration
define('APP_NAME', 'Emam\'s Calculator Suite');
define('APP_URL', 'http://emam-calc.infy.uk');
define('UPLOAD_PATH', 'uploads/avatars/');
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB

// Session configuration
define('SESSION_LIFETIME', 86400); // 24 hours in seconds
define('REMEMBER_LIFETIME', 2592000); // 30 days in seconds

// Email configuration (for password reset)
define('FROM_EMAIL', 'noreply@emamcalc.com');
define('FROM_NAME', 'Emam\'s Calculator Suite');

// Create a PDO database connection
function getDB() {
    try {
        $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        sendResponse(['success' => false, 'message' => 'Database connection failed']);
        exit;
    }
}

// Start session with configuration
session_set_cookie_params([
    'lifetime' => SESSION_LIFETIME,
    'path' => '/',
    'domain' => '',
    'secure' => isset($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();

// Regenerate session ID to prevent fixation
if (!isset($_SESSION['created'])) {
    session_regenerate_id(true);
    $_SESSION['created'] = time();
} elseif (time() - $_SESSION['created'] > 1800) {
    // Regenerate session ID every 30 minutes
    session_regenerate_id(true);
    $_SESSION['created'] = time();
}
?>