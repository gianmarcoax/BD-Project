<?php
session_start();
require_once __DIR__ . '/../../middlewares/auth.php';
include_once '../../helpers/validation.php';
requireAdmin();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard de Administrador</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="dashboard.php">Admin Dashboard</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="elements/peliculas.php">Películas</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="elements/cines_salasyfunciones.php">Cines, Salas y Horarios</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="elements/clientes.php">Clientes</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="elements/boletos.php">Boletos</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="elements/concesiones.php">Concesiones</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="elements/promociones.php">Promociones</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="elements/empleados.php">Empleados</a>
                </li>
            </ul>
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="../../../auth/logout.php">Cerrar sesión</a>
                </li>
            </ul>
        </div>
    </nav>
    <div class="container">
        <h2 class="mt-5">Dashboard de Administrador</h2>
        <p>Bienvenido, <?php echo htmlspecialchars($_SESSION['username']); ?>!</p>
        <p>Aquí puedes gestionar películas, cines, horarios y más.</p>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
