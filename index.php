<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'src/middlewares/auth.php';
require_once 'config/db_connect.php';

// Verificar si se ha cerrado sesión
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: index.php');
    exit();
}

checkSessionTimeout();

if (isLoggedIn()) {
    $username = $_SESSION['username'];
}

// Establecer la codificación a UTF-8
$conn->set_charset("utf8mb4");

// Obtener películas en cartelera
$sql = "SELECT * FROM Peliculas LIMIT 5"; // Limitamos a 5 para este ejemplo
$result = $conn->query($sql);
$peliculas = $result->fetch_all(MYSQLI_ASSOC);
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cine - Página Principal</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="public/css/styles.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="#">Cine</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
            <?php if (isLoggedIn()): ?>
                <li class="nav-item">
                    <a class="nav-link" href="src/views/user/configuracion.php">Bienvenido, <?php echo htmlspecialchars($username); ?></a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="index.php?logout=1">Logout</a>
                </li>
            <?php else: ?>
                <li class="nav-item">
                    <a class="nav-link" href="auth/register.php">Sign Up</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="auth/login.php">Login</a>
                </li>
            <?php endif; ?>
        </ul>
    </div>
</nav>

    <div class="container mt-5">
        <h1>Bienvenido a nuestro Cine</h1>
        <h2>Películas en cartelera</h2>
        <div class="row">
            <?php foreach ($peliculas as $pelicula): ?>
                <div class="col-md-4 mb-4">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title"><?php echo htmlspecialchars($pelicula['Titulo']); ?></h5>
                            <p class="card-text">Género: <?php echo htmlspecialchars($pelicula['Genero']); ?></p>
                            <p class="card-text">Duración: <?php echo htmlspecialchars($pelicula['Duracion']); ?> minutos</p>
                            <a href="#" class="btn btn-primary">Ver detalles</a>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script src="public/js/scripts.js"></script>
</body>
</html>
