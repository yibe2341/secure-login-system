
<?php

require_once __DIR__ . '/includes/auth.php';

// Only administrators can access this page
requireAdmin();

// Prevent caching of administrator information
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Safely escape output
function escapeAdmin($value): string
{
    return htmlspecialchars(
        (string) ($value ?? ''),
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

// Handle account activation/deactivation requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $token = $_POST['csrf_token'] ?? '';

    // Verify CSRF token
    if (
        !is_string($token) ||
        !hash_equals($_SESSION['csrf_token'], $token)
    ) {
        http_response_code(403);
        exit('Invalid security token. Please refresh the page and try again.');
    }

    // Validate target user ID
    $targetUserId = filter_var(
        $_POST['user_id'] ?? null,
        FILTER_VALIDATE_INT
    );

    // Validate requested action
    $action = $_POST['action'] ?? '';

    if (
        $targetUserId === false ||
        $targetUserId === null ||
        $targetUserId <= 0 ||
        !is_string($action) ||
        !in_array($action, ['activate', 'deactivate'], true)
    ) {

        $_SESSION['admin_flash'] = [
            'type' => 'error',
            'message' => 'Invalid account management request.'
        ];

    } elseif ($targetUserId === (int) $_SESSION['user_id']) {

        // Prevent administrators from modifying their own account
        $_SESSION['admin_flash'] = [
            'type' => 'error',
            'message' => 'You cannot modify your own administrator account.'
        ];

    } else {

        try {

            // Check whether the target account exists
            $check = $pdo->prepare(
                'SELECT id, role, is_active
                 FROM users
                 WHERE id = :id
                 LIMIT 1'
            );

            $check->execute([
                ':id' => $targetUserId
            ]);

            $targetUser = $check->fetch(PDO::FETCH_ASSOC);

            if (!$targetUser) {

                $_SESSION['admin_flash'] = [
                    'type' => 'error',
                    'message' => 'The selected account does not exist.'
                ];

            } elseif ($targetUser['role'] === 'admin') {

                // Protect all administrator accounts
                $_SESSION['admin_flash'] = [
                    'type' => 'error',
                    'message' => 'Administrator accounts cannot be modified here.'
                ];

            } else {

                $newStatus = ($action === 'activate') ? 1 : 0;

                if ((int) $targetUser['is_active'] === $newStatus) {

                    $_SESSION['admin_flash'] = [
                        'type' => 'error',
                        'message' => 'The account already has the requested status.'
                    ];

                } else {

                    // Update only non-administrator accounts
                    $update = $pdo->prepare(
                        'UPDATE users
                         SET is_active = :status
                         WHERE id = :id
                         AND role <> :admin_role'
                    );

                    $update->execute([
                        ':status' => $newStatus,
                        ':id' => $targetUserId,
                        ':admin_role' => 'admin'
                    ]);

                    if ($update->rowCount() === 1) {

                        $_SESSION['admin_flash'] = [
                            'type' => 'success',
                            'message' => $action === 'activate'
                                ? 'Account activated successfully.'
                                : 'Account deactivated successfully.'
                        ];

                    } else {

                        $_SESSION['admin_flash'] = [
                            'type' => 'error',
                            'message' => 'The account could not be updated. Please refresh and try again.'
                        ];
                    }
                }
            }

        } catch (PDOException $e) {

            error_log('Admin account management error: ' . $e->getMessage());

            $_SESSION['admin_flash'] = [
                'type' => 'error',
                'message' => 'Unable to update the account. Please try again.'
            ];
        }
    }

    // Post/Redirect/Get prevents duplicate submissions
    header('Location: admin.php');
    exit;
}

// Retrieve one-time notification
$flash = $_SESSION['admin_flash'] ?? null;
unset($_SESSION['admin_flash']);

$message = '';
$error = '';

if (is_array($flash)) {

    if (($flash['type'] ?? '') === 'success') {
        $message = $flash['message'] ?? '';
    } elseif (($flash['type'] ?? '') === 'error') {
        $error = $flash['message'] ?? '';
    }
}

// Retrieve registered users and calculate statistics
try {

    $stmt = $pdo->query(
        "SELECT id, username, email, role, is_active
         FROM users
         ORDER BY id DESC"
    );

    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $totalUsers = count($users);
    $activeUsers = 0;
    $totalAdmins = 0;

    foreach ($users as $user) {

        if ((int) $user['is_active'] === 1) {
            $activeUsers++;
        }

        if ($user['role'] === 'admin') {
            $totalAdmins++;
        }
    }

} catch (PDOException $e) {

    error_log('Admin dashboard retrieval error: ' . $e->getMessage());

    http_response_code(500);
    exit('Unable to load administrator information. Please try again later.');
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <meta name="robots" content="noindex, nofollow">

    <title>Admin Dashboard | Secure Login System</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">

    <link rel="preconnect"
          href="https://fonts.gstatic.com"
          crossorigin>

    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
          rel="stylesheet">

    <style>

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', Arial, sans-serif;
            background: #080d1c;
            color: #e5e7eb;
            padding: 35px 20px;
            min-height: 100vh;
        }

        .container {
            max-width: 1150px;
            margin: auto;
        }

        .header {
            margin-bottom: 30px;
        }

        h1 {
            color: #ffffff;
            margin-bottom: 10px;
            font-size: 30px;
        }

        .subtitle {
            color: #9ca3af;
            font-size: 13px;
            line-height: 1.7;
        }

        .admin-badge {
            display: inline-block;
            margin-top: 15px;
            padding: 8px 13px;
            border-radius: 20px;
            background: rgba(124,58,237,.15);
            border: 1px solid rgba(167,139,250,.3);
            color: #c4b5fd;
            font-size: 11px;
            font-weight: 700;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 18px;
            margin-bottom: 30px;
        }

        .card {
            background: #121b32;
            border: 1px solid #263657;
            padding: 25px;
            border-radius: 14px;
            transition: .3s;
        }

        .card:hover {
            transform: translateY(-5px);
            border-color: #6366f1;
        }

        .card h3 {
            color: #a5b4fc;
            font-size: 13px;
            margin-bottom: 14px;
        }

        .number {
            font-size: 32px;
            font-weight: 800;
            color: #ffffff;
        }

        .table-box {
            background: #121b32;
            border: 1px solid #263657;
            padding: 25px;
            border-radius: 14px;
            overflow-x: auto;
        }

        .table-title {
            font-size: 19px;
            margin-bottom: 22px;
            color: #ffffff;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 850px;
        }

        th, td {
            padding: 16px 13px;
            text-align: left;
            border-bottom: 1px solid #263657;
            font-size: 12px;
        }

        th {
            color: #a5b4fc;
            font-weight: 700;
            background: rgba(30,41,59,.35);
        }

        td {
            color: #d1d5db;
        }

        tbody tr:hover td {
            background: rgba(59,130,246,.04);
        }

        .status {
            color: #4ade80;
            font-weight: 700;
        }

        .inactive {
            color: #f87171;
            font-weight: 700;
        }

        .role {
            color: #c4b5fd;
            font-weight: 600;
        }

        .action-form {
            display: inline-block;
        }

        .action-btn {
            border: none;
            border-radius: 7px;
            padding: 9px 12px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            transition: .3s;
            color: white;
            font-family: inherit;
        }

        .activate-btn {
            background: #15803d;
        }

        .activate-btn:hover {
            background: #16a34a;
            transform: translateY(-2px);
        }

        .deactivate-btn {
            background: #b91c1c;
        }

        .deactivate-btn:hover {
            background: #dc2626;
            transform: translateY(-2px);
        }

        .protected-label {
            color: #a5b4fc;
            font-size: 11px;
            font-weight: 600;
        }

        .alert {
            padding: 14px 17px;
            border-radius: 10px;
            margin-bottom: 22px;
            font-size: 13px;
            line-height: 1.6;
        }

        .success-message {
            color: #86efac;
            background: rgba(34,197,94,.12);
            border: 1px solid rgba(34,197,94,.3);
        }

        .error-message {
            color: #fca5a5;
            background: rgba(239,68,68,.12);
            border: 1px solid rgba(239,68,68,.3);
        }

        .empty-message {
            text-align: center;
            color: #9ca3af;
            padding: 30px;
        }

        .back-btn {
            display: inline-block;
            margin-top: 25px;
            padding: 12px 22px;
            background: linear-gradient(110deg,#2563eb,#7c3aed);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 700;
            transition: .3s;
        }

        .back-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(59,130,246,.3);
        }

        .footer {
            margin-top: 30px;
            text-align: center;
            color: #64748b;
            font-size: 11px;
        }

        @media(max-width:600px) {

            body {
                padding: 20px 12px;
            }

            h1 {
                font-size: 24px;
            }

            .table-box {
                padding: 15px;
            }

            .card {
                padding: 20px;
            }
        }

    </style>

</head>

<body>

<div class="container">

    <header class="header">

        <h1>Administrator Dashboard</h1>

        <p class="subtitle">
            Manage users, monitor accounts, and control system access.
        </p>

        <div class="admin-badge">
            ADMINISTRATOR CONTROL PANEL
        </div>

    </header>

    <!-- Success and error messages -->

    <?php if ($message): ?>

        <div class="alert success-message" role="status">
            <?php echo escapeAdmin($message); ?>
        </div>

    <?php endif; ?>

    <?php if ($error): ?>

        <div class="alert error-message" role="alert">
            <?php echo escapeAdmin($error); ?>
        </div>

    <?php endif; ?>

    <!-- Dashboard statistics -->

    <section class="stats">

        <div class="card">

            <h3>Total Registered Users</h3>

            <div class="number">
                <?php echo $totalUsers; ?>
            </div>

        </div>

        <div class="card">

            <h3>Active Accounts</h3>

            <div class="number">
                <?php echo $activeUsers; ?>
            </div>

        </div>

        <div class="card">

            <h3>Administrator Accounts</h3>

            <div class="number">
                <?php echo $totalAdmins; ?>
            </div>

        </div>

    </section>

    <!-- Registered users table -->

    <section class="table-box">

        <h2 class="table-title">
            Registered Users
        </h2>

        <table>

            <thead>

                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Account Status</th>
                    <th>Account Management</th>
                </tr>

            </thead>

            <tbody>

                <?php if (empty($users)): ?>

                    <tr>

                        <td colspan="6" class="empty-message">
                            No registered users found.
                        </td>

                    </tr>

                <?php else: ?>

                    <?php foreach ($users as $user): ?>

                        <tr>

                            <td>
                                <?php echo escapeAdmin($user['id']); ?>
                            </td>

                            <td>
                                <?php echo escapeAdmin($user['username']); ?>
                            </td>

                            <td>
                                <?php echo escapeAdmin($user['email']); ?>
                            </td>

                            <td class="role">
                                <?php echo escapeAdmin($user['role']); ?>
                            </td>

                            <td>

                                <?php if ((int) $user['is_active'] === 1): ?>

                                    <span class="status">
                                        Active
                                    </span>

                                <?php else: ?>

                                    <span class="inactive">
                                        Inactive
                                    </span>

                                <?php endif; ?>

                            </td>

                            <td>

                                <?php if (
                                    (int) $user['id'] === (int) $_SESSION['user_id']
                                    || $user['role'] === 'admin'
                                ): ?>

                                    <span class="protected-label">
                                        Protected
                                    </span>

                                <?php elseif ((int) $user['is_active'] === 1): ?>

                                    <form
                                        method="POST"
                                        action="admin.php"
                                        class="action-form"
                                        onsubmit="return confirm('Are you sure you want to deactivate this account?');"
                                    >

                                        <input
                                            type="hidden"
                                            name="csrf_token"
                                            value="<?php echo escapeAdmin($_SESSION['csrf_token']); ?>"
                                        >

                                        <input
                                            type="hidden"
                                            name="user_id"
                                            value="<?php echo escapeAdmin($user['id']); ?>"
                                        >

                                        <input
                                            type="hidden"
                                            name="action"
                                            value="deactivate"
                                        >

                                        <button
                                            type="submit"
                                            class="action-btn deactivate-btn"
                                        >
                                            Deactivate
                                        </button>

                                    </form>

                                <?php else: ?>

                                    <form
                                        method="POST"
                                        action="admin.php"
                                        class="action-form"
                                        onsubmit="return confirm('Are you sure you want to activate this account?');"
                                    >

                                        <input
                                            type="hidden"
                                            name="csrf_token"
                                            value="<?php echo escapeAdmin($_SESSION['csrf_token']); ?>"
                                        >

                                        <input
                                            type="hidden"
                                            name="user_id"
                                            value="<?php echo escapeAdmin($user['id']); ?>"
                                        >

                                        <input
                                            type="hidden"
                                            name="action"
                                            value="activate"
                                        >

                                        <button
                                            type="submit"
                                            class="action-btn activate-btn"
                                        >
                                            Activate
                                        </button>

                                    </form>

                                <?php endif; ?>

                            </td>

                        </tr>

                    <?php endforeach; ?>

                <?php endif; ?>

            </tbody>

        </table>

    </section>

    <a href="dashboard.php" class="back-btn">
        ← Back to Dashboard
    </a>

    <footer class="footer">

        Secure Login and Access Control System

        <br><br>

        &copy; <?php echo date('Y'); ?> Secure Access System.
        All rights reserved.

    </footer>

</div>

</body>
</html>
