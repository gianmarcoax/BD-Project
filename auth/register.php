<?php
require_once '../config/db_connect.php';
require_once '../src/helpers/validation.php';
require_once '../src/controllers/AuthController.php';

session_start();

$error_messages = [];

// Verificación del token CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }
}

// Generar un nuevo token CSRF para cada solicitud
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Manejo de registro de usuarios
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitización de entradas
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password']; // No sanitizamos la contraseña para no afectar su complejidad

    // Validaciones de back-end
    if (empty($username) || empty($email) || empty($password)) {
        $error_messages[] = "Todos los campos son obligatorios.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_messages[] = "Correo electrónico no válido.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
        $error_messages[] = "El nombre de usuario debe tener entre 3 y 20 caracteres y solo puede contener letras, números y guiones bajos.";
    } elseif (strlen($password) < 8 || !preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password)) {
        $error_messages[] = "La contraseña debe tener al menos 8 caracteres, incluir mayúsculas, minúsculas, números y caracteres especiales.";
    } elseif (isUsernameTaken($username)) {
        $error_messages[] = "El nombre de usuario ya está en uso.";
    } elseif (isEmailTaken($email)) {
        $error_messages[] = "El correo electrónico ya está en uso.";
    } else {
        if (register($username, $email, $password)) {
            // Registro exitoso
            $_SESSION['registration_success'] = true;
            header('Location: login.php');
            exit();
        } else {
            $error_messages[] = "Error al registrar el usuario. Por favor, intenta nuevamente.";
        }
    }
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro de Usuario</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <script>
        function validateForm() {
            // ... (mantén el código JavaScript de validación del formulario)
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <h2 class="mt-5">Registro de Usuario</h2>
                <?php if (!empty($error_messages)): ?>
                    <div class="alert alert-danger" id="error">
                        <?php foreach ($error_messages as $error_message): ?>
                            <p><?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?></p>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="alert alert-danger" id="error" style="display:none;"></div>
                <?php endif; ?>
                <form action="" method="post" onsubmit="return validateForm()">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div class="form-group">
                        <label for="username">Nombre de Usuario</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Correo Electrónico</label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Contraseña</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Confirmar Contraseña</label>
                        <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                    </div>
                    <div class="g-recaptcha" data-sitekey="YOUR_RECAPTCHA_SITE_KEY"></div>
                    <button type="submit" class="btn btn-primary mt-3">Registrarse</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>