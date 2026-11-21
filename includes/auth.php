
<?php

// Load the database connection.
require_once __DIR__ . '/../config/database.php';

// Configure and start a secure PHP session.
if (session_status() === PHP_SESSION_NONE) {

    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_strict_mode', '1');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => !empty($_SERVER['HTTPS']) &&
                    $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    session_start();
}

// Session inactivity limit: 20 minutes.
$idleTimeout = 1200;

if (isset($_SESSION['last_activity'])) {

    if (time() - $_SESSION['last_activity'] > $idleTimeout) {

        $_SESSION = [];

        if (ini_get('session.use_cookies')) {

            $params = session_get_cookie_params();

            setcookie(
                session_name(),
                '',
                [
                    'expires' => time() - 42000,
                    'path' => $params['path'],
                    'domain' => $params['domain'],
                    'secure' => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite']
                ]
            );
        }

        session_destroy();

        header('Location: login.php?timeout=1');
        exit;
    }
}

$_SESSION['last_activity'] = time();

/**
 * Destroy the current authenticated session.
 */
function destroyUserSession(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {

        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite']
            ]
        );
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

/**
 * Check whether the user is authenticated,
 * active, and using a valid session version.
 */
function requireLogin(): void
{
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }

    global $pdo;

    try {

        $stmt = $pdo->prepare(
            "SELECT is_active, role, session_version
             FROM users
             WHERE id = :id
             LIMIT 1"
        );

        $stmt->execute([
            ':id' => $_SESSION['user_id']
        ]);

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Reject deleted or deactivated accounts.
        if (!$user || (int) $user['is_active'] !== 1) {

            destroyUserSession();

            header('Location: login.php?account=inactive');
            exit;
        }

        // Reject sessions created before a password/security change.
        if (
            !isset($_SESSION['session_version']) ||
            (int) $_SESSION['session_version'] !==
            (int) $user['session_version']
        ) {

            destroyUserSession();

            header('Location: login.php?session=expired');
            exit;
        }

        // Synchronize the session role with the database.
        $_SESSION['user_role'] = $user['role'];

    } catch (PDOException $e) {

        error_log(
            'Authentication check failed: ' . $e->getMessage()
        );

        http_response_code(503);

        exit(
            'Unable to verify your account. Please try again later.'
        );
    }
}

/**
 * Check whether the authenticated user is an administrator.
 */
function requireAdmin(): void
{
    requireLogin();

    if (
        !isset($_SESSION['user_role']) ||
        $_SESSION['user_role'] !== 'admin'
    ) {

        http_response_code(403);

        exit(
            '403 Forbidden: You are not authorized to access this page.'
        );
    }
}
