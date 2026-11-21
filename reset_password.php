
<?php

require_once __DIR__ . '/includes/auth.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

if (isset($_SESSION['user_id'])) {
    requireLogin();
    header('Location: dashboard.php');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$success = '';

$token = $_GET['token'] ?? $_POST['token'] ?? '';

function escapeResetPassword($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

$validToken = false;
$resetRequest = false;

if (
    is_string($token) &&
    preg_match('/\A[a-f0-9]{64}\z/', $token)
) {
    try {
        $tokenHash = hash('sha256', $token);

        $stmt = $pdo->prepare(
            'SELECT id, email
             FROM password_resets
             WHERE token_hash = :token_hash
               AND used_at IS NULL
               AND expires_at > NOW()
             LIMIT 1'
        );

        $stmt->execute([
            ':token_hash' => $tokenHash
        ]);

        $resetRequest = $stmt->fetch(PDO::FETCH_ASSOC);
        $validToken = (bool) $resetRequest;

    } catch (PDOException $e) {
        error_log('Reset token verification error: ' . $e->getMessage());

        $error = 'Unable to verify your reset request. Please try again later.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$error) {

    $submittedToken = $_POST['csrf_token'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    if (
        !is_string($submittedToken) ||
        !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {
        $error = 'Invalid request. Please refresh the page and try again.';

    } elseif (!$validToken || !$resetRequest) {
        $error = 'This password reset link is invalid, expired, or already used.';

    } elseif (
        !is_string($password) ||
        !is_string($confirmPassword)
    ) {
        $error = 'Please enter valid password information.';

    } elseif (
        strlen($password) < 8 ||
        strlen($password) > 72
    ) {
        $error = 'Your password must contain at least 8 characters and no more than 72 bytes.';

    } elseif ($password !== $confirmPassword) {
        $error = 'The passwords do not match.';

    } else {

        try {
            $newPasswordHash = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            if ($newPasswordHash === false) {
                throw new RuntimeException('Password hashing failed.');
            }

            $pdo->beginTransaction();

            // Consume the reset token only if it is still valid.
            $consumeStmt = $pdo->prepare(
                'UPDATE password_resets
                 SET used_at = NOW()
                 WHERE id = :id
                   AND used_at IS NULL
                   AND expires_at > NOW()'
            );

            $consumeStmt->execute([
                ':id' => $resetRequest['id']
            ]);

            if ($consumeStmt->rowCount() !== 1) {
                throw new RuntimeException(
                    'Reset token has already been used or expired.'
                );
            }

            // Change the password and invalidate all existing sessions.
            $updateStmt = $pdo->prepare(
                'UPDATE users
                 SET password_hash = :password_hash,
                     session_version = session_version + 1
                 WHERE email = :email'
            );

            $updateStmt->execute([
                ':password_hash' => $newPasswordHash,
                ':email' => $resetRequest['email']
            ]);

            if ($updateStmt->rowCount() !== 1) {
                throw new RuntimeException(
                    'Unable to update account password.'
                );
            }

            // Invalidate other outstanding reset links for this account.
            $deleteStmt = $pdo->prepare(
                'DELETE FROM password_resets
                 WHERE email = :email
                   AND id <> :current_id'
            );

            $deleteStmt->execute([
                ':email' => $resetRequest['email'],
                ':current_id' => $resetRequest['id']
            ]);

            $pdo->commit();

            $success = 'Your password has been changed successfully. You can now sign in with your new password.';

            $validToken = false;

            // Rotate the CSRF token after the security change.
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        } catch (Throwable $e) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            error_log('Password reset error: ' . $e->getMessage());

            $error = 'Unable to reset your password. Please request a new reset link.';
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Reset Password | Secure Access</title>

    <style>

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: #080e1d;
            color: white;
            font-family: Arial, sans-serif;
        }

        .container {
            width: 100%;
            max-width: 440px;
            padding: 40px;
            background: #101b31;
            border: 1px solid #293b59;
            border-radius: 18px;
            box-shadow: 0 20px 60px rgba(0,0,0,.4);
        }

        h1 {
            margin-bottom: 12px;
            font-size: 27px;
        }

        p {
            color: #a7b6d0;
            font-size: 14px;
            line-height: 1.7;
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 9px;
            font-size: 13px;
            font-weight: bold;
        }

        input {
            width: 100%;
            padding: 14px;
            margin-bottom: 20px;
            border: 1px solid #293b59;
            border-radius: 9px;
            background: #080e1d;
            color: white;
            outline: none;
        }

        input:focus {
            border-color: #3b82f6;
        }

        button {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 9px;
            background: linear-gradient(110deg,#2563eb,#7c3aed);
            color: white;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            opacity: 0.9;
        }

        .message,
        .error {
            padding: 13px;
            margin-bottom: 20px;
            border-radius: 9px;
            font-size: 13px;
            line-height: 1.6;
        }

        .message {
            color: #86efac;
            background: rgba(34,197,94,.12);
            border: 1px solid rgba(34,197,94,.3);
        }

        .error {
            color: #fca5a5;
            background: rgba(239,68,68,.12);
            border: 1px solid rgba(239,68,68,.3);
        }

        a {
            display: block;
            text-align: center;
            margin-top: 22px;
            color: #60a5fa;
            text-decoration: none;
            font-size: 13px;
        }

        a:hover {
            text-decoration: underline;
        }

        @media (max-width: 480px) {
            .container {
                padding: 28px 22px;
            }
        }

    </style>

</head>

<body>

<div class="container">

    <h1>Reset Password</h1>

    <p>
        Create a new password for your account.
        Your reset link is valid for 30 minutes and can only be used once.
    </p>

    <?php if ($error): ?>

        <div class="error" role="alert">
            <?php echo escapeResetPassword($error); ?>
        </div>

    <?php endif; ?>

    <?php if ($success): ?>

        <div class="message" role="status">
            <?php echo escapeResetPassword($success); ?>
        </div>

        <a href="login.php">Go to Sign In</a>

    <?php elseif ($validToken): ?>

        <form method="POST" action="">

            <input
                type="hidden"
                name="csrf_token"
                value="<?php echo escapeResetPassword($_SESSION['csrf_token']); ?>"
            >

            <input
                type="hidden"
                name="token"
                value="<?php echo escapeResetPassword($token); ?>"
            >

            <label for="password">New Password</label>

            <input
                type="password"
                id="password"
                name="password"
                minlength="8"
                maxlength="72"
                autocomplete="new-password"
                placeholder="Enter new password"
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
                placeholder="Confirm new password"
                required
            >

            <button type="submit">
                Update Password
            </button>

        </form>

    <?php elseif (!$error): ?>

        <div class="error">
            This password reset link is invalid, expired, or already used.
            Please request a new one.
        </div>

        <a href="forgot_password.php">Request another reset link</a>

    <?php endif; ?>

    <?php if (!$success): ?>

        <a href="login.php">← Back to Sign In</a>

    <?php endif; ?>

</div>

</body>
</html>
