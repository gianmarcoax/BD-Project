<?php
session_start();
require_once '../../../src/middlewares/auth.php';
require_once '../../../config/db_connect.php';
require_once '../../../src/helpers/validation.php';

requireLogin();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$userId = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Obtener los datos actuales del usuario
$stmt = $conn->prepare("SELECT NombreUsuario, CorreoElectronico FROM Usuarios WHERE ID = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();
$userData = $result->fetch_assoc();
$stmt->close();

$error = '';
$success = '';

// Manejo de actualización de datos
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $action = $_POST['action'];

    switch ($action) {
        case 'update_username':
            $new_username = filter_input(INPUT_POST, 'new_username', FILTER_SANITIZE_STRING);
            $validation_result = validateUsername($new_username);

            if ($validation_result === true) {
                $stmt = $conn->prepare("UPDATE Usuarios SET NombreUsuario = ? WHERE ID = ?");
                $stmt->bind_param("si", $new_username, $userId);
                if ($stmt->execute()) {
                    $_SESSION['username'] = $new_username;
                    $success = "Nombre de usuario actualizado con éxito.";
                } else {
                    $error = "Error al actualizar el nombre de usuario: " . $stmt->error;
                }
                $stmt->close();
            } else {
                $error = $validation_result;
            }
            break;

        case 'update_password':
            $current_password = $_POST['current_password'];
            $new_password = $_POST['new_password'];
            $confirm_password = $_POST['confirm_password'];

            if ($new_password !== $confirm_password) {
                $error = "Las nuevas contraseñas no coinciden.";
            } elseif (!validatePassword($new_password)) {
                $error = "La nueva contraseña no cumple con los requisitos de seguridad.";
            } else {
                $stmt = $conn->prepare("SELECT Contrasena FROM Usuarios WHERE ID = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                $user = $result->fetch_assoc();
                $stmt->close();

                if (password_verify($current_password, $user['Contrasena'])) {
                    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("UPDATE Usuarios SET Contrasena = ? WHERE ID = ?");
                    $stmt->bind_param("si", $hashed_password, $userId);
                    if ($stmt->execute()) {
                        $success = "Contraseña actualizada con éxito. Por favor, inicie sesión nuevamente.";
                        session_destroy();
                        header("Location: ../../../../auth/login.php");
                        exit();
                    } else {
                        $error = "Error al actualizar la contraseña: " . $stmt->error;
                    }
                    $stmt->close();
                } else {
                    $error = "La contraseña actual es incorrecta.";
                }
            }
            break;

        case 'update_email':
            $new_email = filter_input(INPUT_POST, 'new_email', FILTER_SANITIZE_EMAIL);

            if (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
                $error = "Correo electrónico no válido.";
            } else {
                $stmt = $conn->prepare("UPDATE Usuarios SET CorreoElectronico = ? WHERE ID = ?");
                $stmt->bind_param("si", $new_email, $userId);
                if ($stmt->execute()) {
                    $success = "Correo electrónico actualizado con éxito.";
                } else {
                    $error = "Error al actualizar el correo electrónico: " . $stmt->error;
                }
                $stmt->close();
            }
            break;
    }

    // Actualizar los datos del usuario después de los cambios
    if (empty($error) && $action != 'update_password') {
        $stmt = $conn->prepare("SELECT NombreUsuario, CorreoElectronico FROM Usuarios WHERE ID = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $userData = $result->fetch_assoc();
        $stmt->close();
    }
}

// Función de validación de contraseña (agrega esto si no está en tu archivo validation.php)
if (!function_exists('validatePassword')) {
    function validatePassword($password) {
        return strlen($password) >= 8 
            && preg_match('/[A-Z]/', $password) 
            && preg_match('/[a-z]/', $password) 
            && preg_match('/[0-9]/', $password);
    }
}

?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuración del Usuario</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="../../../../public/css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="../../../../index.php">Cine</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="../../../../index.php">Inicio</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../../../../auth/logout.php">Cerrar sesión</a>
                </li>
            </ul>
        </div>
    </nav>

    <div class="container mt-5">
        <h2>Configuración del Usuario</h2>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <form action="configuracion.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="action" value="update_username">
            <div class="form-group">
                <label for="new_username">Nuevo Nombre de Usuario</label>
                <input type="text" class="form-control" id="new_username" name="new_username" value="<?php echo htmlspecialchars($userData['NombreUsuario']); ?>" required>
            </div>
            <button type="submit" class="btn btn-primary">Actualizar Nombre de Usuario</button>
        </form>

        <hr>

        <form action="configuracion.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="action" value="update_password">
            <div class="form-group">
                <label for="current_password">Contraseña Actual</label>
                <input type="password" class="form-control" id="current_password" name="current_password" required>
            </div>
            <div class="form-group">
                <label for="new_password">Nueva Contraseña</label>
                <input type="password" class="form-control" id="new_password" name="new_password" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirmar Nueva Contraseña</label>
                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn btn-primary">Actualizar Contraseña</button>
        </form>

        <hr>

        <form action="configuracion.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" name="action" value="update_email">
            <div class="form-group">
                <label for="new_email">Nuevo Correo Electrónico</label>
                <input type="email" class="form-control" id="new_email" name="new_email" value="<?php echo htmlspecialchars($userData['CorreoElectronico']); ?>" required>
            </div>
            <button type="submit" class="btn btn-primary">Actualizar Correo Electrónico</button>
        </form>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script src="../../../../public/js/scripts.js"></script>
</body>
</html>