
<?php

require_once __DIR__ . '/includes/auth.php';

requireLogin();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');

global $pdo;

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {
        http_response_code(403);
        exit('Invalid request. Please refresh the page and try again.');
    }

    $currentPassword = $_POST['current_password'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    if (
        !is_string($currentPassword) ||
        !is_string($newPassword) ||
        !is_string($confirmPassword)
    ) {
        $error = 'Invalid form submission.';

    } elseif (
        $currentPassword === '' ||
        $newPassword === '' ||
        $confirmPassword === ''
    ) {
        $error = 'Please complete all password fields.';

    } elseif (strlen($newPassword) < 8) {
        $error = 'Your new password must contain at least 8 characters.';

    } elseif (strlen($newPassword) > 72) {
        $error = 'Your new password is too long.';

    } elseif ($newPassword !== $confirmPassword) {
        $error = 'The new passwords do not match.';

    } else {

        try {

            $stmt = $pdo->prepare(
                "SELECT password_hash, email, session_version
                 FROM users
                 WHERE id = :id
                 LIMIT 1"
            );

            $stmt->execute([
                ':id' => $_SESSION['user_id']
            ]);

            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                destroyUserSession();
                header('Location: login.php');
                exit;
            }

            if (!password_verify($currentPassword, $user['password_hash'])) {

                $error = 'Your current password is incorrect.';

            } elseif (password_verify($newPassword, $user['password_hash'])) {

                $error = 'Your new password must be different from your current password.';

            } else {

                $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

                if ($newHash === false) {
                    throw new RuntimeException('Password hashing failed.');
                }

                $pdo->beginTransaction();

                // Change password and invalidate other sessions.
                $update = $pdo->prepare(
                    "UPDATE users
                     SET password_hash = :password_hash,
                         session_version = session_version + 1
                     WHERE id = :id"
                );

                $update->execute([
                    ':password_hash' => $newHash,
                    ':id' => $_SESSION['user_id']
                ]);

                if ($update->rowCount() !== 1) {
                    throw new RuntimeException('Password update failed.');
                }

                // Get the new session version for this current session.
                $versionStmt = $pdo->prepare(
                    "SELECT session_version
                     FROM users
                     WHERE id = :id
                     LIMIT 1"
                );

                $versionStmt->execute([
                    ':id' => $_SESSION['user_id']
                ]);

                $newVersion = $versionStmt->fetchColumn();

                if ($newVersion === false) {
                    throw new RuntimeException('Unable to verify session version.');
                }

                // Invalidate outstanding password reset links.
                $delete = $pdo->prepare(
                    "DELETE FROM password_resets
                     WHERE email = :email"
                );

                $delete->execute([
                    ':email' => $user['email']
                ]);

                $pdo->commit();

                // Keep the current session valid.
                $_SESSION['session_version'] = (int) $newVersion;

                // Regenerate the session ID.
                session_regenerate_id(true);

                // Rotate the CSRF token.
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                $success = 'Your password has been changed successfully.';
            }

        } catch (Throwable $e) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            error_log('Password change failed: ' . $e->getMessage());

            $error = 'Unable to change your password. Please try again.';
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Change Password | Secure Login System</title>

    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: #0b1220;
            color: #e0e0e0;
        }

        .container {
            width: 100%;
            max-width: 450px;
            background: #151f32;
            padding: 35px;
            border-radius: 12px;
            border: 1px solid #263650;
            box-shadow: 0 15px 40px rgba(0,0,0,.3);
        }

        h1 {
            color: #ffffff;
            margin-bottom: 10px;
            font-size: 26px;
        }

        .subtitle {
            color: #aab6c8;
            margin-bottom: 25px;
            line-height: 1.5;
        }

        label {
            display: block;
            margin: 17px 0 8px;
            font-size: 14px;
        }

        input {
            width: 100%;
            padding: 13px;
            border: 1px solid #34445e;
            border-radius: 7px;
            background: #0b1220;
            color: white;
            font-size: 15px;
        }

        input:focus {
            outline: 2px solid #4b83e6;
            border-color: transparent;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 14px;
            border: none;
            border-radius: 7px;
            background: #1a237e;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #283593;
        }

        .message {
            padding: 12px;
            border-radius: 7px;
            margin-bottom: 18px;
            line-height: 1.5;
        }

        .error {
            background: #49232b;
            color: #ffb9c2;
        }

        .success {
            background: #173d31;
            color: #a8f0ce;
        }

        .links {
            margin-top: 22px;
            text-align: center;
        }

        .links a {
            color: #91b8ff;
            text-decoration: none;
            font-size: 14px;
        }

        .links a:hover {
            text-decoration: underline;
        }

        @media (max-width: 480px) {
            .container {
                padding: 25px 20px;
            }
        }
    </style>
</head>

<body>

<div class="container">

    <h1>Change Password</h1>

    <p class="subtitle">
        Update your account password to keep your account secure.
    </p>

    <?php if ($error !== ''): ?>

        <div class="message error" role="alert">
            <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
        </div>

    <?php endif; ?>

    <?php if ($success !== ''): ?>

        <div class="message success" role="status">
            <?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?>
        </div>

    <?php else: ?>

        <form method="POST" action="change_password.php">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>"
            >

            <label for="current_password">Current Password</label>

            <input
                type="password"
                id="current_password"
                name="current_password"
                autocomplete="current-password"
                required
            >

            <label for="new_password">New Password</label>

            <input
                type="password"
                id="new_password"
                name="new_password"
                minlength="8"
                maxlength="72"
                autocomplete="new-password"
                required
            >

            <label for="confirm_password">Confirm New Password</label>

            <input
                type="password"
                id="confirm_password"
                name="confirm_password"
                minlength="8"
                maxlength="72"
                autocomplete="new-password"
                required
            >

            <button type="submit">Update Password</button>

        </form>

    <?php endif; ?>

    <div class="links">
        <a href="dashboard.php">Back to Dashboard</a>
    </div>

</div>

</body>
</html>
