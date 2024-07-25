<?php
session_start();
require_once __DIR__ . '/../../../middlewares/auth.php';
require_once __DIR__ . '/../../../helpers/validation.php';
require_once __DIR__ . '/../../../../config/db_connect.php';

requireAdmin();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$validationData = validatePelicula();
$validGeneros = $validationData['generos'];
$validClasificaciones = $validationData['clasificaciones'];

$peliculaEdit = null;
if (isset($_GET['edit'])) {
    $id = $_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM Peliculas WHERE ID=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $peliculaEdit = $result->fetch_assoc();
    // Escapar datos de usuario para evitar XSS
    foreach ($peliculaEdit as &$value) {
        $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }
}

// Manejo de operaciones CRUD
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $titulo = $_POST['titulo'] ?? '';
    $genero = $_POST['genero'] ?? '';
    $duracion = $_POST['duracion'] ?? 0;
    $clasificacion = $_POST['clasificacion'] ?? '';
    $director = $_POST['director'] ?? '';
    $actoresPrincipales = $_POST['actoresPrincipales'] ?? '';

    $validationResult = validatePelicula($genero, $duracion, $clasificacion);
    if ($validationResult !== true) {
        $error = $validationResult;
    } else {
        if (isset($_POST['id']) && !empty($_POST['id'])) {
            // Actualizar película existente
            $id = $_POST['id'];
            $stmt = $conn->prepare("UPDATE Peliculas SET Titulo=?, Genero=?, Duracion=?, Clasificacion=?, Director=?, ActoresPrincipales=? WHERE ID=?");
            $stmt->bind_param("ssisssi", $titulo, $genero, $duracion, $clasificacion, $director, $actoresPrincipales, $id);
        } else {
            // Insertar nueva película
            $stmt = $conn->prepare("INSERT INTO Peliculas (Titulo, Genero, Duracion, Clasificacion, Director, ActoresPrincipales) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssisss", $titulo, $genero, $duracion, $clasificacion, $director, $actoresPrincipales);
        }

        if ($stmt->execute()) {
            header('Location: peliculas.php');
            exit();
        } else {
            $error = "Error al guardar la película: " . $stmt->error;
        }
    }
}

// Manejo de eliminación
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM Peliculas WHERE ID=?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header('Location: peliculas.php');
        exit();
    } else {
        $error = "Error al eliminar la película: " . $stmt->error;
    }
}

// Manejo de búsqueda y paginación AJAX
if (isset($_GET['ajax']) && $_GET['ajax'] == '1') {
    $search = $_GET['search'] ?? '';
    $page = isset($_GET['page']) ? $_GET['page'] : 1;
    $limit = 6; // Número de películas por página
    $offset = ($page - 1) * $limit;

    $stmt = $conn->prepare("SELECT * FROM Peliculas WHERE Titulo LIKE CONCAT('%',?,'%') OR Genero LIKE CONCAT('%',?,'%') OR Director LIKE CONCAT('%',?,'%') OR ActoresPrincipales LIKE CONCAT('%',?,'%') LIMIT ? OFFSET ?");
    $stmt->bind_param("ssssii", $search, $search, $search, $search, $limit, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    $peliculas = $result->fetch_all(MYSQLI_ASSOC);

    // Escapar datos de usuario para evitar XSS
    foreach ($peliculas as &$pelicula) {
        foreach ($pelicula as &$value) {
            $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    // Obtener el número total de películas para la paginación
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM Peliculas WHERE Titulo LIKE CONCAT('%',?,'%') OR Genero LIKE CONCAT('%',?,'%') OR Director LIKE CONCAT('%',?,'%') OR ActoresPrincipales LIKE CONCAT('%',?,'%')");
    $stmt->bind_param("ssss", $search, $search, $search, $search);
    $stmt->execute();
    $result = $stmt->get_result();
    $totalPeliculas = $result->fetch_assoc()['count'];
    $totalPages = ceil($totalPeliculas / $limit);

    echo json_encode(['peliculas' => $peliculas, 'totalPages' => $totalPages]);
    exit();
}

// Paginación
$limit = 6; // Número de películas por página
$page = isset($_GET['page']) ? $_GET['page'] : 1;
$offset = ($page - 1) * $limit;

// Búsqueda
$search = isset($_GET['search']) ? $_GET['search'] : '';

// Obtener todas las películas con paginación y búsqueda
$stmt = $conn->prepare("SELECT * FROM Peliculas WHERE Titulo LIKE CONCAT('%',?,'%') OR Genero LIKE CONCAT('%',?,'%') OR Director LIKE CONCAT('%',?,'%') OR ActoresPrincipales LIKE CONCAT('%',?,'%') LIMIT ? OFFSET ?");
$stmt->bind_param("ssssii", $search, $search, $search, $search, $limit, $offset);
$stmt->execute();
$result = $stmt->get_result();
$peliculas = $result->fetch_all(MYSQLI_ASSOC);

// Escapar datos de usuario para evitar XSS
foreach ($peliculas as &$pelicula) {
    foreach ($pelicula as &$value) {
        $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }
}

// Obtener el número total de películas para la paginación
$stmt = $conn->prepare("SELECT COUNT(*) as count FROM Peliculas WHERE Titulo LIKE CONCAT('%',?,'%') OR Genero LIKE CONCAT('%',?,'%') OR Director LIKE CONCAT('%',?,'%') OR ActoresPrincipales LIKE CONCAT('%',?,'%')");
$stmt->bind_param("ssss", $search, $search, $search, $search);
$stmt->execute();
$result = $stmt->get_result();
$totalPeliculas = $result->fetch_assoc()['count'];
$totalPages = ceil($totalPeliculas / $limit);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Películas</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script>
        function fetchPeliculas(search, page) {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', 'peliculas.php?ajax=1&search=' + encodeURIComponent(search) + '&page=' + page, true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText);
                    const peliculas = response.peliculas;
                    const totalPages = response.totalPages;

                    let html = '';
                    for (let pelicula of peliculas) {
                        html += `<tr>
                            <td>${pelicula.ID}</td>
                            <td>${pelicula.Titulo}</td>
                            <td>${pelicula.Genero}</td>
                            <td>${pelicula.Duracion}</td>
                            <td>${pelicula.Clasificacion}</td>
                            <td>${pelicula.Director}</td>
                            <td>${pelicula.ActoresPrincipales}</td>
                            <td>
                                <a href="peliculas.php?edit=${pelicula.ID}" class="btn btn-sm btn-warning">Editar</a>
                                <a href="peliculas.php?delete=${pelicula.ID}" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar esta película?');">Eliminar</a>
                            </td>
                        </tr>`;
                    }
                    document.querySelector('tbody').innerHTML = html;

                    // Actualizar la paginación
                    let paginationHtml = '';
                    for (let i = 1; i <= totalPages; i++) {
                        paginationHtml += `<li class="page-item ${i == page ? 'active' : ''}">
                            <a class="page-link" href="#" onclick="fetchPeliculas('${search}', ${i}); return false;">${i}</a>
                        </li>`;
                    }
                    document.querySelector('.pagination').innerHTML = paginationHtml;
                }
            };
            xhr.send();
        }

        document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.querySelector('input[name="search"]');
            searchInput.addEventListener('input', function() {
                fetchPeliculas(searchInput.value, 1);
            });

            // Inicializar la primera carga de películas
            fetchPeliculas(searchInput.value, 1);
        });
    </script>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Admin Dashboard</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="../elements/peliculas.php">Películas</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../elements/cines_salasyfunciones.php">Cines, Salas y Horarios</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../elements/clientes.php">Clientes</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../elements/boletos.php">Boletos</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../elements/concesiones.php">Concesiones</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../elements/promociones.php">Promociones</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../elements/empleados.php">Empleados</a>
                </li>
            </ul>
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="../../../../auth/logout.php">Cerrar sesión</a>
                </li>
            </ul>
        </div>
    </nav>

    <div class="container">
        <h2 class="mt-5">Gestionar Películas</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form action="" method="post" class="mb-4">
            <input type="hidden" name="id" value="<?php echo $peliculaEdit['ID'] ?? ''; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <label for="titulo">Título</label>
                <input type="text" class="form-control" id="titulo" name="titulo" value="<?php echo $peliculaEdit['Titulo'] ?? ''; ?>" required>
            </div>
            <div class="form-group">
                <label for="genero">Género</label>
                <select class="form-control" id="genero" name="genero" required>
                    <?php foreach ($validGeneros as $genero): ?>
                        <option value="<?php echo $genero; ?>" <?php echo (isset($peliculaEdit['Genero']) && $peliculaEdit['Genero'] == $genero) ? 'selected' : ''; ?>>
                            <?php echo $genero; ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label for="duracion">Duración (minutos)</label>
                <input type="number" class="form-control" id="duracion" name="duracion" value="<?php echo $peliculaEdit['Duracion'] ?? ''; ?>" required>
            </div>
            <div class="form-group">
                <label for="clasificacion">Clasificación</label>
                <select class="form-control" id="clasificacion" name="clasificacion" required>
                    <?php foreach ($validClasificaciones as $clasificacion): ?>
                        <option value="<?php echo $clasificacion; ?>" <?php echo (isset($peliculaEdit['Clasificacion']) && $peliculaEdit['Clasificacion'] == $clasificacion) ? 'selected' : ''; ?>>
                            <?php echo $clasificacion; ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label for="director">Director</label>
                <input type="text" class="form-control" id="director" name="director" value="<?php echo $peliculaEdit['Director'] ?? ''; ?>" required>
            </div>
            <div class="form-group">
                <label for="actoresPrincipales">Actores Principales</label>
                <input type="text" class="form-control" id="actoresPrincipales" name="actoresPrincipales" value="<?php echo $peliculaEdit['ActoresPrincipales'] ?? ''; ?>" required>
            </div>
            <button type="submit" class="btn btn-primary">Guardar</button>
        </form>

        <form method="get" action="peliculas.php" class="mb-4">
            <div class="input-group">
                <input type="text" class="form-control" name="search" placeholder="Buscar por título, género, director, actores" value="<?php echo htmlspecialchars($search); ?>">
                <div class="input-group-append">
                    <button class="btn btn-outline-secondary" type="submit">Buscar</button>
                </div>
            </div>
        </form>

        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Título</th>
                    <th>Género</th>
                    <th>Duración</th>
                    <th>Clasificación</th>
                    <th>Director</th>
                    <th>Actores Principales</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <!-- Los datos se llenarán a través de AJAX -->
            </tbody>
        </table>

        <nav aria-label="Page navigation example">
            <ul class="pagination">
                <!-- La paginación se llenará a través de AJAX -->
            </ul>
        </nav>
    </div>
</body>
</html>
