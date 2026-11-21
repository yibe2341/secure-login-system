
<?php

require_once __DIR__ . '/includes/auth.php';

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: login.php');
    exit;
}

// Verify CSRF token
$submittedToken = $_POST['csrf_token'] ?? '';

if (
    !is_string($submittedToken) ||
    empty($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $submittedToken)
) {
    http_response_code(403);
    exit('Invalid logout request.');
}

// Destroy the authenticated session and its cookie
destroyUserSession();

// Redirect to login page
header('Location: login.php?logout=success');
exit;
