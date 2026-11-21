
<?php

session_start();

require_once __DIR__ . '/config/database.php';

// Prevent caching of registration responses.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Generate CSRF token.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Initialize variables.
$errors = [];
$success = '';

$username = '';
$email = '';
$password = '';
$confirmPassword = '';

// Process registration.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Verify CSRF token.
    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {

        $errors[] = 'Invalid request. Please refresh the page and try again.';

    } else {

        // Collect submitted information.
        $rawUsername = $_POST['username'] ?? '';
        $rawEmail = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if (
            !is_string($rawUsername) ||
            !is_string($rawEmail) ||
            !is_string($password) ||
            !is_string($confirmPassword)
        ) {

            $errors[] = 'Invalid form submission. Please try again.';

        } else {

            $username = trim($rawUsername);
            $email = trim($rawEmail);

            // Username validation.
            if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {

                $errors[] = 'Username must contain 3-50 characters and only letters, numbers, and underscores.';
            }

            // Email validation.
            if (
                strlen($email) > 100 ||
                !filter_var($email, FILTER_VALIDATE_EMAIL)
            ) {

                $errors[] = 'Please enter a valid email address.';
            }

            // Password validation.
            if (
                strlen($password) < 12 ||
                strlen($password) > 72
            ) {

                $errors[] = 'Password must contain between 12 and 72 bytes.';
            }

            // Password confirmation.
            if ($password !== $confirmPassword) {

                $errors[] = 'Passwords do not match.';
            }

            // Create account.
            if (empty($errors)) {

                try {

                    // Check existing username or email.
                    $check = $pdo->prepare(
                        'SELECT id
                         FROM users
                         WHERE username = :username
                            OR email = :email
                         LIMIT 1'
                    );

                    $check->execute([
                        ':username' => $username,
                        ':email' => $email
                    ]);

                    if ($check->fetch()) {

                        $errors[] = 'Username or email is already registered.';

                    } else {

                        // Hash password.
                        $passwordHash = password_hash(
                            $password,
                            PASSWORD_DEFAULT
                        );

                        if ($passwordHash === false) {
                            throw new RuntimeException(
                                'Password hashing failed.'
                            );
                        }

                        // Register account with ordinary user role.
                        $insert = $pdo->prepare(
                            'INSERT INTO users
                                (username, email, password_hash, role)
                             VALUES
                                (:username, :email, :password_hash, :role)'
                        );

                        $insert->execute([
                            ':username' => $username,
                            ':email' => $email,
                            ':password_hash' => $passwordHash,
                            ':role' => 'user'
                        ]);

                        $success = 'Your account has been created successfully! You can now sign in.';

                        // Clear password fields.
                        $password = '';
                        $confirmPassword = '';

                        // Generate a new CSRF token.
                        $_SESSION['csrf_token'] = bin2hex(
                            random_bytes(32)
                        );
                    }

                } catch (PDOException $e) {

                    error_log(
                        'Registration database error: ' .
                        $e->getMessage()
                    );

                    if ($e->getCode() === '23000') {

                        $errors[] = 'Username or email is already registered.';

                    } else {

                        $errors[] = 'Something went wrong. Please try again later.';
                    }

                } catch (RuntimeException $e) {

                    error_log(
                        'Registration error: ' . $e->getMessage()
                    );

                    $errors[] = 'Unable to create your account. Please try again later.';
                }
            }
        }
    }
}

// Safely escape output.
function escapeOutput($value): string
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        'UTF-8'
    );
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <meta name="description"
          content="Create a secure account using our protected registration system.">

    <title>Create Account | Secure Access</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">

    <link rel="preconnect"
          href="https://fonts.gstatic.com"
          crossorigin>

    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
          rel="stylesheet">

    <style>

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            background: #080e1d;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 35px 18px;
            overflow-x: hidden;
        }

        /* Animated background */

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
            from {
                transform: translate(0, 0);
            }

            to {
                transform: translate(70px, 60px);
            }
        }

        /* Main layout */

        .wrapper {
            width: 100%;
            max-width: 1050px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            background: rgba(16, 27, 49, .78);
            border: 1px solid rgba(255,255,255,.12);
            border-radius: 24px;
            overflow: hidden;
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

        /* Left panel */

        .info-panel {
            padding: 55px 42px;
            background: linear-gradient(
                145deg,
                #142c59,
                #101b37 75%
            );
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
            letter-spacing: .5px;
        }

        .brand-icon {
            width: 43px;
            height: 43px;
            display: grid;
            place-items: center;
            border-radius: 13px;
            background: linear-gradient(135deg, #3b82f6, #7c3aed);
            box-shadow: 0 5px 20px rgba(59,130,246,.4);
            font-size: 23px;
        }

        .info-content {
            margin: 75px 0;
        }

        .tag {
            display: inline-block;
            color: #93c5fd;
            background: rgba(59,130,246,.12);
            border: 1px solid rgba(147,197,253,.25);
            padding: 8px 13px;
            border-radius: 30px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            margin-bottom: 24px;
        }

        .info-content h1 {
            font-size: clamp(30px, 4vw, 43px);
            line-height: 1.2;
            margin-bottom: 20px;
        }

        .info-content h1 span {
            color: #60a5fa;
        }

        .info-content p {
            color: #a7b6d0;
            line-height: 1.8;
            font-size: 14px;
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
            background: rgba(96,165,250,.13);
            color: #60a5fa;
            border-radius: 10px;
        }

        .footer {
            color: #7586a5;
            font-size: 11px;
            margin-top: 35px;
        }

        /* Registration panel */

        .form-panel {
            padding: 50px 45px;
        }

        .form-header {
            margin-bottom: 28px;
        }

        .form-header h2 {
            font-size: 27px;
            margin-bottom: 10px;
        }

        .form-header p {
            color: #9caac0;
            font-size: 13px;
        }

        .field {
            margin-bottom: 19px;
        }

        .field label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: #d9e4f5;
            margin-bottom: 9px;
        }

        .input-wrap {
            position: relative;
        }

        .input-wrap input {
            width: 100%;
            padding: 14px 45px 14px 15px;
            background: rgba(7,16,33,.8);
            border: 1px solid #293b59;
            border-radius: 11px;
            color: #fff;
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
            box-shadow:
                0 0 0 3px rgba(59,130,246,.13),
                0 0 18px rgba(59,130,246,.12);
        }

        .input-icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #8194b2;
            font-size: 16px;
        }

        .toggle {
            cursor: pointer;
            border: none;
            background: none;
            color: #8fa4c3;
        }

        .toggle:hover {
            color: #60a5fa;
        }

        /* Password strength */

        .strength-container {
            margin-top: 10px;
        }

        .strength-bars {
            display: flex;
            gap: 5px;
        }

        .strength-bars span {
            height: 4px;
            flex: 1;
            background: #293b59;
            border-radius: 5px;
            transition: .3s;
        }

        .strength-text {
            color: #8fa4c3;
            font-size: 10px;
            margin-top: 7px;
        }

        /* Alerts */

        .alert {
            padding: 13px;
            border-radius: 10px;
            margin-bottom: 17px;
            font-size: 12px;
            line-height: 1.6;
        }

        .error {
            background: rgba(239,68,68,.12);
            border: 1px solid rgba(239,68,68,.3);
            color: #fca5a5;
        }

        .success {
            background: rgba(34,197,94,.12);
            border: 1px solid rgba(34,197,94,.3);
            color: #86efac;
        }

        /* Button */

        .submit-btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 11px;
            background: linear-gradient(110deg, #2563eb, #7c3aed);
            color: white;
            font-size: 13px;
            font-weight: 700;
            font-family: inherit;
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

        .login-link {
            text-align: center;
            color: #9caac0;
            font-size: 12px;
            margin-top: 24px;
        }

        .login-link a {
            color: #60a5fa;
            text-decoration: none;
            font-weight: 700;
        }

        .login-link a:hover {
            text-decoration: underline;
        }

        .security-note {
            text-align: center;
            margin-top: 26px;
            font-size: 10px;
            color: #71839e;
        }

        /* Mobile */

        @media(max-width: 760px) {

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
                padding: 35px 27px;
            }
        }

        @media(prefers-reduced-motion: reduce) {

            *,
            *::before,
            *::after {
                animation-duration: .01ms !important;
                animation-iteration-count: 1 !important;
                scroll-behavior: auto !important;
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

    <!-- Left information panel -->

    <section class="info-panel">

        <div class="brand">

            <div class="brand-icon">⛨</div>

            <span>
                SECURE<span style="color:#60a5fa">ACCESS</span>
            </span>

        </div>

        <div class="info-content">

            <div class="tag">CYBERSECURITY PROJECT</div>

            <h1>
                Your Security.<br>
                Your <span>Identity.</span><br>
                Your Control.
            </h1>

            <p>
                Experience a secure and reliable authentication
                environment designed to protect your digital identity
                and keep your account information safe.
            </p>

        </div>

        <div class="features">

            <div class="feature">
                <div class="feature-icon">✓</div>
                Secure account registration
            </div>

            <div class="feature">
                <div class="feature-icon">⌑</div>
                Password protection
            </div>

            <div class="feature">
                <div class="feature-icon">◈</div>
                Controlled user access
            </div>

        </div>

        <div class="footer">
            © 2026 Secure Access System. All rights reserved.
        </div>

    </section>

    <!-- Registration form -->

    <section class="form-panel">

        <div class="form-header">

            <h2>Create Account</h2>

            <p>
                Join us today. It only takes a few moments.
            </p>

        </div>

        <!-- Error messages -->

        <?php foreach ($errors as $error): ?>

            <div class="alert error">
                <?php echo escapeOutput($error); ?>
            </div>

        <?php endforeach; ?>

        <!-- Success message -->

        <?php if ($success): ?>

            <div class="alert success">
                ✓ <?php echo escapeOutput($success); ?>
            </div>

        <?php endif; ?>

        <form method="POST"
              action=""
              autocomplete="on">

            <!-- CSRF protection -->

            <input
                type="hidden"
                name="csrf_token"
                value="<?php echo escapeOutput($_SESSION['csrf_token']); ?>"
            >

            <!-- Username -->

            <div class="field">

                <label for="username">Username</label>

                <div class="input-wrap">

                    <input
                        id="username"
                        type="text"
                        name="username"
                        maxlength="50"
                        value="<?php echo escapeOutput($username); ?>"
                        placeholder="Choose a username"
                        autocomplete="username"
                        required
                    >

                    <span class="input-icon">♙</span>

                </div>

            </div>

            <!-- Email -->

            <div class="field">

                <label for="email">Email Address</label>

                <div class="input-wrap">

                    <input
                        id="email"
                        type="email"
                        name="email"
                        maxlength="100"
                        value="<?php echo escapeOutput($email); ?>"
                        placeholder="you@example.com"
                        autocomplete="email"
                        required
                    >

                    <span class="input-icon">✉</span>

                </div>

            </div>

            <!-- Password -->

            <div class="field">

                <label for="password">Password</label>

                <div class="input-wrap">

                    <input
                        id="password"
                        type="password"
                        name="password"
                        minlength="12"
                        maxlength="72"
                        placeholder="Create a strong password"
                        autocomplete="new-password"
                        required
                    >

                    <button
                        type="button"
                        class="input-icon toggle"
                        data-toggle="password"
                        aria-label="Show password"
                        aria-pressed="false"
                    >◉</button>

                </div>

                <!-- Password strength indicator -->

                <div class="strength-container">

                    <div class="strength-bars">

                        <span></span>
                        <span></span>
                        <span></span>
                        <span></span>

                    </div>

                    <div class="strength-text" id="strengthText">
                        Password strength: Not entered
                    </div>

                </div>

            </div>

            <!-- Confirm password -->

            <div class="field">

                <label for="confirm_password">
                    Confirm Password
                </label>

                <div class="input-wrap">

                    <input
                        id="confirm_password"
                        type="password"
                        name="confirm_password"
                        minlength="12"
                        maxlength="72"
                        placeholder="Enter your password again"
                        autocomplete="new-password"
                        required
                    >

                    <button
                        type="button"
                        class="input-icon toggle"
                        data-toggle="confirm_password"
                        aria-label="Show confirm password"
                        aria-pressed="false"
                    >◉</button>

                </div>

            </div>

            <!-- Submit -->

            <button
                type="submit"
                class="submit-btn"
            >
                Create Secure Account →
            </button>

        </form>

        <div class="login-link">

            Already have an account?

            <a href="login.php">Sign in</a>

        </div>

        <div class="security-note">
            ⛨ Your password is protected using secure hashing.
        </div>

    </section>

</div>

<script>

// Show and hide passwords.

document.querySelectorAll('[data-toggle]').forEach(button => {

    button.addEventListener('click', function () {

        const input = document.getElementById(
            this.dataset.toggle
        );

        const showing = input.type === 'password';

        input.type = showing ? 'text' : 'password';

        this.setAttribute(
            'aria-pressed',
            String(showing)
        );

        this.setAttribute(
            'aria-label',
            showing ? 'Hide password' : 'Show password'
        );

    });

});


// Password strength indicator.

const password = document.getElementById('password');

const bars = document.querySelectorAll(
    '.strength-bars span'
);

const strengthText = document.getElementById('strengthText');

password.addEventListener('input', function () {

    const value = this.value;

    let score = 0;

    if (value.length >= 12) score++;

    if (/[a-z]/.test(value) && /[A-Z]/.test(value)) {
        score++;
    }

    if (/[0-9]/.test(value)) score++;

    if (/[^a-zA-Z0-9]/.test(value)) score++;

    const colors = [
        '#ef4444',
        '#f59e0b',
        '#3b82f6',
        '#22c55e'
    ];

    bars.forEach((bar, index) => {

        bar.style.background =
            index < score
                ? colors[score - 1]
                : '#293b59';

    });

    const labels = [
        'Password strength: Not entered',
        'Password strength: Weak',
        'Password strength: Fair',
        'Password strength: Good',
        'Password strength: Strong'
    ];

    strengthText.textContent = labels[score];

});

</script>

</body>
</html>
