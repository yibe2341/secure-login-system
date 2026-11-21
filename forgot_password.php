
<?php

require_once __DIR__ . '/includes/auth.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (isset($_SESSION['user_id'])) {
    requireLogin();
    header('Location: dashboard.php');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
$error = '';
$developmentLink = '';

function escapeForgotPassword($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $submittedToken = $_POST['csrf_token'] ?? '';
    $email = $_POST['email'] ?? '';

    if (
        !is_string($submittedToken) ||
        !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {
        $error = 'Invalid request. Please refresh the page and try again.';

    } elseif (!is_string($email)) {
        $error = 'Please enter a valid email address.';

    } else {

        $email = trim($email);

        if (
            $email === '' ||
            strlen($email) > 255 ||
            !filter_var($email, FILTER_VALIDATE_EMAIL)
        ) {
            $error = 'Please enter a valid email address.';

        } else {

            try {

                $stmt = $pdo->prepare(
                    'SELECT id, email FROM users WHERE email = :email LIMIT 1'
                );

                $stmt->execute([':email' => $email]);

                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                // Always use the same general response.
                $message = 'If an account with that email exists, a password reset request has been created.';

                if ($user) {

                    // Generate a cryptographically secure token.
                    $plainToken = bin2hex(random_bytes(32));

                    // Store only the SHA-256 hash of the token.
                    $tokenHash = hash('sha256', $plainToken);

                    // Remove previous reset requests for this email.
                    $deleteStmt = $pdo->prepare(
                        'DELETE FROM password_resets WHERE email = :email'
                    );

                    $deleteStmt->execute([
                        ':email' => $user['email']
                    ]);

                    // Store a new token that expires in 30 minutes.
                    $insertStmt = $pdo->prepare(
                        "INSERT INTO password_resets
                            (email, token_hash, expires_at)
                         VALUES
                            (:email, :token_hash,
                             DATE_ADD(NOW(), INTERVAL 30 MINUTE))"
                    );

                    $insertStmt->execute([
                        ':email' => $user['email'],
                        ':token_hash' => $tokenHash
                    ]);

                    /*
                     * LOCAL DEVELOPMENT ONLY.
                     * Replace this with private email delivery
                     * before deploying the system publicly.
                     */
                    $developmentLink =
                        'http://localhost/secure-login-system/reset_password.php?token='
                        . urlencode($plainToken);
                }

            } catch (PDOException $e) {

                error_log(
                    'Forgot password database error: ' . $e->getMessage()
                );

                $error = 'Unable to process your request. Please try again later.';
            }
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password | Secure Access</title>

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
            margin-bottom: 24px;
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

        .message, .error, .development {
            padding: 13px;
            margin-bottom: 20px;
            border-radius: 9px;
            font-size: 13px;
            line-height: 1.6;
            overflow-wrap: anywhere;
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

        .development {
            color: #fde68a;
            background: rgba(234,179,8,.1);
            border: 1px solid rgba(234,179,8,.3);
        }

        .development a {
            color: #93c5fd;
            overflow-wrap: anywhere;
        }

        .back {
            display: block;
            text-align: center;
            margin-top: 22px;
            color: #60a5fa;
            text-decoration: none;
            font-size: 13px;
        }
    </style>
</head>

<body>

<div class="container">

    <h1>Forgot Password?</h1>

    <p>
        Enter the email address associated with your account.
        We will create a password reset request.
    </p>

    <?php if ($message): ?>
        <div class="message">
            <?php echo escapeForgotPassword($message); ?>
        </div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="error" role="alert">
            <?php echo escapeForgotPassword($error); ?>
        </div>
    <?php endif; ?>

    <?php if ($developmentLink): ?>
        <div class="development">
            <strong>Local development reset link:</strong><br><br>

            <a href="<?php echo escapeForgotPassword($developmentLink); ?>">
                Open password reset page
            </a>

            <br><br>

            <small>
                Development only. Do not expose reset links this way
                on a public website.
            </small>
        </div>
    <?php endif; ?>

    <form method="POST" action="">

        <input
            type="hidden"
            name="csrf_token"
            value="<?php echo escapeForgotPassword($_SESSION['csrf_token']); ?>"
        >

        <label for="email">Registered Email Address</label>

        <input
            type="email"
            id="email"
            name="email"
            placeholder="Enter your registered email"
            maxlength="255"
            autocomplete="email"
            required
        >

        <button type="submit">
            Create Reset Request
        </button>

    </form>

    <a class="back" href="login.php">
        ← Back to Sign In
    </a>

</div>

</body>
</html>
