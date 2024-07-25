<?php
session_start();
require_once '../../middlewares/auth.php';
require_once '../../../config/db_connect.php';

// Verificar si el usuario está logueado
requireLogin();

// Obtener películas en cartelera
$sql = "SELECT * FROM Peliculas";
$result = $conn->query($sql);
$peliculas = $result->fetch_all(MYSQLI_ASSOC);

// Obtener promociones activas
$sql_promociones = "SELECT * FROM Promociones WHERE FechaInicio <= CURDATE() AND FechaFin >= CURDATE()";
$result_promociones = $conn->query($sql_promociones);
$promociones = $result_promociones->fetch_all(MYSQLI_ASSOC);
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cine GMAC - Página Principal</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="../../../public/css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Cine GMAC</a>
        <div class="navbar-nav ml-auto">
            <span class="navbar-text mr-3">
                Bienvenido, <?php echo htmlspecialchars($_SESSION['username']); ?>
            </span>
            <a class="nav-item nav-link" href="../../../auth/logout.php">Cerrar Sesión</a>
        </div>
    </nav>

    <div class="container mt-5">
        <h1 class="text-center mb-4">Cartelera</h1>
        <div class="row">
            <?php foreach ($peliculas as $pelicula): ?>
                <div class="col-md-4 mb-4">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title"><?php echo htmlspecialchars($pelicula['Titulo']); ?></h5>
                            <p class="card-text">Género: <?php echo htmlspecialchars($pelicula['Genero']); ?></p>
                            <p class="card-text">Duración: <?php echo htmlspecialchars($pelicula['Duracion']); ?> minutos</p>
                            <p class="card-text">Director: <?php echo htmlspecialchars($pelicula['Director']); ?></p>
                            <a href="#" class="btn btn-primary">Comprar Boletos</a>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <h2 class="text-center mb-4 mt-5">Promociones Activas</h2>
        <div class="row">
            <?php foreach ($promociones as $promocion): ?>
                <div class="col-md-6 mb-4">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title"><?php echo htmlspecialchars($promocion['NombrePromocion']); ?></h5>
                            <p class="card-text"><?php echo htmlspecialchars($promocion['Descripcion']); ?></p>
                            <p class="card-text">Descuento: <?php echo htmlspecialchars($promocion['Descuento'] * 100); ?>%</p>
                            <p class="card-text">Válido hasta: <?php echo htmlspecialchars($promocion['FechaFin']); ?></p>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script src="../../../public/js/scripts.js"></script>
</body>
</html>