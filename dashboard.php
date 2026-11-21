
<?php

require_once __DIR__ . '/includes/auth.php';

// Protect dashboard from unauthorized access.
requireLogin();

// Prevent browsers from caching this protected page.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Safely escape output.
function escapeDashboard($value): string
{
    return htmlspecialchars(
        (string) ($value ?? ''),
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

// Ensure a CSRF token exists.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Retrieve authenticated user information.
$username = $_SESSION['username'] ?? 'User';
$role = $_SESSION['user_role'] ?? 'user';

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">

    <title>Dashboard | Secure Access</title>

    <link
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
        rel="stylesheet"
    >

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            padding: 30px;
            background: #080e1d;
            color: #ffffff;
            font-family: 'Inter', sans-serif;
        }

        .container {
            max-width: 1000px;
            margin: 50px auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 40px;
        }

        .brand {
            font-weight: 800;
            font-size: 20px;
            letter-spacing: 1px;
        }

        .brand span {
            color: #60a5fa;
        }

        .welcome {
            padding: 40px;
            border-radius: 20px;
            border: 1px solid #293b59;
            background: linear-gradient(135deg, #142c59, #101b37);
            animation: appear .7s ease-out;
        }

        @keyframes appear {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .welcome h1 {
            font-size: 32px;
            margin-top: 0;
        }

        .welcome p {
            color: #a7b6d0;
            line-height: 1.8;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 25px;
        }

        .card {
            padding: 25px;
            background: #111f3b;
            border: 1px solid #293b59;
            border-radius: 15px;
            transition: .3s;
        }

        .card:hover {
            transform: translateY(-5px);
            border-color: #3b82f6;
        }

        .card h3 {
            color: #60a5fa;
        }

        .card p {
            color: #a7b6d0;
            font-size: 13px;
            line-height: 1.7;
        }

        .card-link {
            display: inline-block;
            margin-top: 10px;
            color: #93c5fd;
            font-size: 13px;
            font-weight: 600;
            text-decoration: none;
        }

        .card-link:hover {
            color: #ffffff;
            text-decoration: underline;
        }

        .role {
            display: inline-block;
            padding: 7px 14px;
            border-radius: 30px;
            background: rgba(59, 130, 246, .15);
            color: #93c5fd;
            font-size: 12px;
            margin-top: 10px;
        }

        .logout {
            display: inline-block;
            padding: 12px 20px;
            background: linear-gradient(110deg, #2563eb, #7c3aed);
            border: none;
            border-radius: 9px;
            color: white;
            font-weight: 700;
            cursor: pointer;
            font-family: inherit;
            transition: .3s;
        }

        .logout:hover {
            opacity: .85;
            transform: translateY(-2px);
        }

        .footer {
            margin-top: 35px;
            text-align: center;
            color: #64748b;
            font-size: 12px;
        }

        @media (max-width: 600px) {
            body {
                padding: 15px;
            }

            .container {
                margin: 25px auto;
            }

            .welcome {
                padding: 25px;
            }

            .welcome h1 {
                font-size: 25px;
            }

            .header {
                margin-bottom: 25px;
            }

            .logout {
                padding: 10px 15px;
            }
        }
    </style>
</head>

<body>

<div class="container">

    <header class="header">

        <div class="brand">
            SECURE<span>ACCESS</span>
        </div>

        <form action="logout.php" method="POST">

            <input
                type="hidden"
                name="csrf_token"
                value="<?php echo escapeDashboard($_SESSION['csrf_token']); ?>"
            >

            <button type="submit" class="logout">
                Sign Out →
            </button>

        </form>

    </header>

    <main>

        <section class="welcome">

            <h1>
                Welcome, <?php echo escapeDashboard($username); ?>!
            </h1>

            <p>
                You have successfully authenticated.
                Your account is now accessing the protected dashboard.
            </p>

            <div class="role">
                Account role: <?php echo escapeDashboard($role); ?>
            </div>

        </section>

        <section class="cards">

            <div class="card">

                <h3>Account Security</h3>

                <p>
                    Your account is authenticated through the
                    secure login system.
                </p>

            </div>

            <div class="card">

                <h3>Access Control</h3>

                <p>
                    Your permissions are determined by your
                    assigned account role.
                </p>

            </div>

            <div class="card">

                <h3>Session Status</h3>

                <p>
                    Your current session is active.
                    Your account is protected by session authentication.
                </p>

            </div>

            <div class="card">

                <h3>Account Settings</h3>

                <p>
                    Manage your account password and improve
                    the security of your account.
                </p>

                <a href="change_password.php" class="card-link">
                    Change Password →
                </a>

            </div>

        </section>

    </main>

    <footer class="footer">
        &copy; <?php echo date('Y'); ?> Secure Access System.
        All rights reserved.
    </footer>

</div>

</body>
</html>
