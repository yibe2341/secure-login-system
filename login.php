
<?php

require_once __DIR__ . '/includes/auth.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_MINUTES', 15);

function getLoginClientIp(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';

    if (!is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return 'unknown';
    }

    return $ip;
}

function escapeLogin($value): string
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

// Redirect already authenticated users according to their role.
if (isset($_SESSION['user_id'])) {
    requireLogin();

    if ($_SESSION['user_role'] === 'admin') {
        header('Location: admin.php');
    } else {
        header('Location: dashboard.php');
    }

    exit;
}

// Generate CSRF token.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$identifier = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {
        $error = 'Invalid request. Please refresh the page and try again.';

    } else {

        $rawIdentifier = $_POST['identifier'] ?? '';
        $password = $_POST['password'] ?? '';

        if (
            !is_string($rawIdentifier) ||
            !is_string($password)
        ) {
            $error = 'Please enter valid login credentials.';

        } else {

            $identifier = trim($rawIdentifier);

            if (
                $identifier === '' ||
                strlen($identifier) > 100 ||
                $password === '' ||
                strlen($password) > 72
            ) {
                $error = 'Please enter valid login credentials.';

            } else {

                $rateLimitIdentifier = strtolower($identifier);
                $ipAddress = getLoginClientIp();

                try {

                    // Check failed login attempts within the lockout period.
                    $attemptStmt = $pdo->prepare(
                        "SELECT COUNT(*) AS total_attempts
                         FROM login_attempts
                         WHERE identifier = :identifier
                           AND ip_address = :ip_address
                           AND attempted_at >=
                               DATE_SUB(NOW(), INTERVAL " .
                               LOGIN_LOCKOUT_MINUTES . " MINUTE)"
                    );

                    $attemptStmt->execute([
                        ':identifier' => $rateLimitIdentifier,
                        ':ip_address' => $ipAddress
                    ]);

                    $attemptData = $attemptStmt->fetch(PDO::FETCH_ASSOC);
                    $attemptCount = (int) ($attemptData['total_attempts'] ?? 0);

                    if ($attemptCount >= MAX_LOGIN_ATTEMPTS) {

                        $error = 'Too many unsuccessful login attempts. Please wait 15 minutes before trying again.';

                    } else {

                        // Retrieve account including its session version.
                        $stmt = $pdo->prepare(
                            "SELECT
                                id,
                                username,
                                email,
                                password_hash,
                                role,
                                is_active,
                                session_version
                             FROM users
                             WHERE username = :username
                                OR email = :email
                             LIMIT 1"
                        );

                        $stmt->execute([
                            ':username' => $identifier,
                            ':email' => $identifier
                        ]);

                        $user = $stmt->fetch(PDO::FETCH_ASSOC);

                        if (
                            $user &&
                            (int) $user['is_active'] === 1 &&
                            password_verify($password, $user['password_hash'])
                        ) {

                            // Clear failed attempts after successful login.
                            $deleteStmt = $pdo->prepare(
                                "DELETE FROM login_attempts
                                 WHERE identifier = :identifier
                                   AND ip_address = :ip_address"
                            );

                            $deleteStmt->execute([
                                ':identifier' => $rateLimitIdentifier,
                                ':ip_address' => $ipAddress
                            ]);

                            // Regenerate session ID after authentication.
                            if (!session_regenerate_id(true)) {
                                throw new RuntimeException(
                                    'Unable to regenerate session ID.'
                                );
                            }

                            // Store authenticated user information.
                            $_SESSION['user_id'] = (int) $user['id'];
                            $_SESSION['username'] = $user['username'];
                            $_SESSION['user_role'] = $user['role'];

                            // Store database session version.
                            $_SESSION['session_version'] =
                                (int) $user['session_version'];

                            $_SESSION['last_activity'] = time();

                            // Rotate CSRF token.
                            $_SESSION['csrf_token'] = bin2hex(
                                random_bytes(32)
                            );

                            // Redirect according to account role.
                            if ($user['role'] === 'admin') {
                                header('Location: admin.php');
                            } else {
                                header('Location: dashboard.php');
                            }

                            exit;

                        } else {

                            // Record failed login attempt.
                            $insertAttempt = $pdo->prepare(
                                "INSERT INTO login_attempts
                                    (identifier, ip_address, attempted_at)
                                 VALUES
                                    (:identifier, :ip_address, NOW())"
                            );

                            $insertAttempt->execute([
                                ':identifier' => $rateLimitIdentifier,
                                ':ip_address' => $ipAddress
                            ]);

                            $error = 'Invalid username/email or password.';
                        }
                    }

                } catch (PDOException $e) {

                    error_log('Login database error: ' . $e->getMessage());

                    $error = 'Unable to process your login. Please try again later.';

                } catch (RuntimeException $e) {

                    error_log('Login session error: ' . $e->getMessage());

                    $error = 'Unable to establish a secure session. Please try again.';
                }
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

    <meta name="description" content="Secure login and authentication system.">

    <title>Sign In | Secure Access</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

    <link
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
        rel="stylesheet"
    >

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
            padding: 25px 15px;
            background: #080e1d;
            color: white;
            font-family: 'Inter', sans-serif;
            overflow-x: hidden;
        }

        .background {
            position: fixed;
            inset: 0;
            overflow: hidden;
            z-index: -1;
        }

        .orb {
            position: absolute;
            width: 400px;
            height: 400px;
            border-radius: 50%;
            filter: blur(100px);
            opacity: .35;
            animation: float 10s infinite alternate ease-in-out;
        }

        .orb.one {
            background: #2563eb;
            top: -130px;
            left: -100px;
        }

        .orb.two {
            background: #7c3aed;
            bottom: -150px;
            right: -100px;
            animation-delay: 2s;
        }

        @keyframes float {
            to {
                transform: translate(70px, 60px);
            }
        }

        .wrapper {
            width: 100%;
            max-width: 1000px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            border: 1px solid rgba(255,255,255,.12);
            border-radius: 24px;
            overflow: hidden;
            background: rgba(16,27,49,.85);
            backdrop-filter: blur(20px);
            box-shadow: 0 25px 80px rgba(0,0,0,.45);
            animation: appear .8s ease-out;
        }

        @keyframes appear {
            from {
                opacity: 0;
                transform: translateY(30px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .info-panel {
            padding: 55px 42px;
            background: linear-gradient(145deg,#142c59,#101b37);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 17px;
            font-weight: 800;
        }

        .brand-icon {
            width: 43px;
            height: 43px;
            display: grid;
            place-items: center;
            border-radius: 13px;
            background: linear-gradient(135deg,#3b82f6,#7c3aed);
            font-size: 23px;
            box-shadow: 0 5px 20px rgba(59,130,246,.4);
        }

        .info-content {
            margin: 70px 0;
        }

        .tag {
            display: inline-block;
            padding: 8px 13px;
            border-radius: 30px;
            color: #93c5fd;
            background: rgba(59,130,246,.12);
            border: 1px solid rgba(147,197,253,.25);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            margin-bottom: 24px;
        }

        .info-content h1 {
            font-size: 40px;
            line-height: 1.25;
            margin-bottom: 20px;
        }

        .info-content h1 span {
            color: #60a5fa;
        }

        .info-content p {
            color: #a7b6d0;
            font-size: 14px;
            line-height: 1.8;
        }

        .features {
            display: grid;
            gap: 17px;
        }

        .feature {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #d5e2f5;
            font-size: 13px;
        }

        .feature-icon {
            width: 34px;
            height: 34px;
            display: grid;
            place-items: center;
            border-radius: 10px;
            color: #60a5fa;
            background: rgba(96,165,250,.13);
        }

        .footer {
            color: #7586a5;
            font-size: 11px;
            margin-top: 35px;
        }

        .form-panel {
            padding: 60px 45px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .form-header {
            margin-bottom: 35px;
        }

        .form-header h2 {
            font-size: 29px;
            margin-bottom: 10px;
        }

        .form-header p {
            color: #9caac0;
            font-size: 13px;
            line-height: 1.7;
        }

        .field {
            margin-bottom: 23px;
        }

        .field label {
            display: block;
            margin-bottom: 9px;
            font-size: 12px;
            font-weight: 600;
            color: #d9e4f5;
        }

        .input-wrap {
            position: relative;
        }

        .input-wrap input {
            width: 100%;
            padding: 15px 45px 15px 15px;
            background: rgba(7,16,33,.8);
            border: 1px solid #293b59;
            border-radius: 11px;
            color: white;
            outline: none;
            font-family: inherit;
            font-size: 13px;
            transition: .3s;
        }

        .input-wrap input::placeholder {
            color: #64748b;
        }

        .input-wrap input:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59,130,246,.13);
        }

        .input-icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #8194b2;
            font-size: 17px;
        }

        .toggle {
            cursor: pointer;
            background: none;
            border: none;
        }

        .toggle:hover {
            color: #60a5fa;
        }

        .alert {
            padding: 13px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 12px;
            line-height: 1.6;
        }

        .error {
            color: #fca5a5;
            background: rgba(239,68,68,.12);
            border: 1px solid rgba(239,68,68,.3);
        }

        .forgot-password {
            display: block;
            text-align: right;
            margin-top: -5px;
            margin-bottom: 20px;
            color: #60a5fa;
            font-size: 12px;
            font-weight: 600;
            text-decoration: none;
            transition: .3s;
        }

        .forgot-password:hover {
            color: #93c5fd;
            text-decoration: underline;
        }

        .submit-btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 11px;
            background: linear-gradient(110deg,#2563eb,#7c3aed);
            color: white;
            font-family: inherit;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            transition: .3s;
            box-shadow: 0 8px 25px rgba(37,99,235,.22);
        }

        .submit-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 30px rgba(37,99,235,.4);
        }

        .submit-btn:active {
            transform: scale(.98);
        }

        .register-link {
            text-align: center;
            color: #9caac0;
            font-size: 12px;
            margin-top: 27px;
        }

        .register-link a {
            color: #60a5fa;
            text-decoration: none;
            font-weight: 700;
        }

        .register-link a:hover {
            text-decoration: underline;
        }

        .security-note {
            text-align: center;
            margin-top: 35px;
            color: #71839e;
            font-size: 10px;
        }

        @media(max-width:760px) {

            .wrapper {
                grid-template-columns: 1fr;
                max-width: 480px;
            }

            .info-panel {
                padding: 30px;
            }

            .info-content {
                margin: 35px 0;
            }

            .info-content h1 {
                font-size: 30px;
            }

            .features {
                display: none;
            }

            .form-panel {
                padding: 40px 27px;
            }
        }

        @media(prefers-reduced-motion:reduce) {

            *,
            *::before,
            *::after {
                animation-duration: .01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: .01ms !important;
            }
        }

    </style>

</head>

<body>

<div class="background">
    <div class="orb one"></div>
    <div class="orb two"></div>
</div>

<div class="wrapper">

    <section class="info-panel">

        <div class="brand">
            <div class="brand-icon">⛨</div>
            <span>SECURE<span style="color:#60a5fa">ACCESS</span></span>
        </div>

        <div class="info-content">

            <div class="tag">SECURE AUTHENTICATION</div>

            <h1>
                Welcome<br>
                <span>Back.</span>
            </h1>

            <p>
                Sign in to your account and access your
                secure digital environment. Your identity
                and account security matter to us.
            </p>

        </div>

        <div class="features">

            <div class="feature">
                <div class="feature-icon">✓</div>
                Protected account access
            </div>

            <div class="feature">
                <div class="feature-icon">⌑</div>
                Secure password verification
            </div>

            <div class="feature">
                <div class="feature-icon">◈</div>
                Controlled user permissions
            </div>

        </div>

        <div class="footer">
            © 2026 Secure Access System. All rights reserved.
        </div>

    </section>

    <section class="form-panel">

        <div class="form-header">
            <h2>Sign In</h2>
            <p>Enter your account details to continue.</p>
        </div>

        <?php if ($error !== ''): ?>
            <div class="alert error" role="alert">
                <?php echo escapeLogin($error); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="" autocomplete="on">

            <input
                type="hidden"
                name="csrf_token"
                value="<?php echo escapeLogin($_SESSION['csrf_token']); ?>"
            >

            <div class="field">

                <label for="identifier">Username or Email</label>

                <div class="input-wrap">

                    <input
                        id="identifier"
                        type="text"
                        name="identifier"
                        value="<?php echo escapeLogin($identifier); ?>"
                        placeholder="Enter username or email"
                        autocomplete="username"
                        maxlength="100"
                        required
                    >

                    <span class="input-icon">♙</span>

                </div>

            </div>

            <div class="field">

                <label for="password">Password</label>

                <div class="input-wrap">

                    <input
                        id="password"
                        type="password"
                        name="password"
                        placeholder="Enter your password"
                        autocomplete="current-password"
                        maxlength="72"
                        required
                    >

                    <button
                        type="button"
                        class="input-icon toggle"
                        id="togglePassword"
                        aria-label="Show password"
                        aria-pressed="false"
                    >◉</button>

                </div>

            </div>

            <a href="forgot_password.php" class="forgot-password">
                Forgot your password?
            </a>

            <button type="submit" class="submit-btn">
                Sign In Securely →
            </button>

        </form>

        <div class="register-link">
            Don't have an account?
            <a href="register.php">Create Account</a>
        </div>

        <div class="security-note">
            ⛨ Secure authentication environment
        </div>

    </section>

</div>

<script>

const togglePassword = document.getElementById('togglePassword');
const passwordInput = document.getElementById('password');

togglePassword.addEventListener('click', function () {

    const showing = passwordInput.type === 'password';

    passwordInput.type = showing ? 'text' : 'password';

    this.setAttribute('aria-pressed', String(showing));

    this.setAttribute(
        'aria-label',
        showing ? 'Hide password' : 'Show password'
    );

});

</script>

</body>
</html>
