<?php
session_start();
require_once __DIR__ . '/../../../middlewares/auth.php';
require_once __DIR__ . '/../../../helpers/validation.php';
require_once __DIR__ . '/../../../../config/db_connect.php';

requireAdmin();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$items_per_page = 6;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($page - 1) * $items_per_page;

// Establecer la codificación a UTF-8
$conn->set_charset("utf8mb4");

// Manejo de búsqueda y paginación AJAX
if (isset($_GET['ajax']) && $_GET['ajax'] == '1') {
    $search = $_GET['search'] ?? '';
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $offset = ($page - 1) * $items_per_page;

    $stmt = $conn->prepare("SELECT * FROM Concesiones WHERE NombreProducto LIKE CONCAT('%',?,'%') OR Descripcion LIKE CONCAT('%',?,'%') OR Categoria LIKE CONCAT('%',?,'%') LIMIT ? OFFSET ?");
    $stmt->bind_param("sssii", $search, $search, $search, $items_per_page, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    $concesiones = $result->fetch_all(MYSQLI_ASSOC);

    // Escapar datos de usuario para evitar XSS
    foreach ($concesiones as &$concesion) {
        foreach ($concesion as &$value) {
            $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    // Obtener el número total de concesiones para la paginación
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM Concesiones WHERE NombreProducto LIKE CONCAT('%',?,'%') OR Descripcion LIKE CONCAT('%',?,'%') OR Categoria LIKE CONCAT('%',?,'%')");
    $stmt->bind_param("sss", $search, $search, $search);
    $stmt->execute();
    $result = $stmt->get_result();
    $totalConcesiones = $result->fetch_assoc()['count'];
    $totalPages = ceil($totalConcesiones / $items_per_page);

    echo json_encode(['concesiones' => $concesiones, 'totalPages' => $totalPages]);
    exit();
}

$editMode = false;
$concesionEdit = null;

// Obtener datos de concesión para editar
if (isset($_GET['edit'])) {
    $editMode = true;
    $id = $_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM Concesiones WHERE ID = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $concesionEdit = $result->fetch_assoc();
    $stmt->close();
}

// Manejo de operaciones CRUD para concesiones
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $nombre_producto = $_POST['nombre_producto'] ?? '';
    $descripcion = $_POST['descripcion'] ?? '';
    $precio = $_POST['precio'] ?? '';
    $categoria = $_POST['categoria'] ?? '';

    $validationResult = validateConcesion($precio);
    if ($validationResult !== true) {
        $error = $validationResult;
    } else {
        if (isset($_POST['id']) && !empty($_POST['id'])) {
            // Actualizar concesión existente
            $id = $_POST['id'];
            $stmt = $conn->prepare("UPDATE Concesiones SET NombreProducto = ?, Descripcion = ?, Precio = ?, Categoria = ? WHERE ID = ?");
            $stmt->bind_param("ssdsi", $nombre_producto, $descripcion, $precio, $categoria, $id);
        } else {
            // Insertar nueva concesión
            $stmt = $conn->prepare("INSERT INTO Concesiones (NombreProducto, Descripcion, Precio, Categoria) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssds", $nombre_producto, $descripcion, $precio, $categoria);
        }

        if ($stmt->execute()) {
            header("Location: concesiones.php");
            exit();
        } else {
            $error = "Error al guardar la concesión: " . $stmt->error;
        }
        $stmt->close();
    }
}

// Manejo de eliminación
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM Concesiones WHERE ID = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header("Location: concesiones.php");
        exit();
    } else {
        $error = "Error al eliminar la concesión: " . $stmt->error;
    }
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Concesiones</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script>
        function fetchConcesiones(search, page) {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', 'concesiones.php?ajax=1&search=' + encodeURIComponent(search) + '&page=' + page, true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText);
                    const concesiones = response.concesiones;
                    const totalPages = response.totalPages;

                    let html = '';
                    for (let concesion of concesiones) {
                        html += `<tr>
                            <td>${concesion.ID}</td>
                            <td>${concesion.NombreProducto}</td>
                            <td>${concesion.Descripcion}</td>
                            <td>${concesion.Precio}</td>
                            <td>${concesion.Categoria}</td>
                            <td>
                                <a href="concesiones.php?edit=${concesion.ID}" class="btn btn-sm btn-warning">Editar</a>
                                <a href="concesiones.php?delete=${concesion.ID}" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar esta concesión?');">Eliminar</a>
                            </td>
                        </tr>`;
                    }
                    document.querySelector('tbody').innerHTML = html;

                    // Actualizar la paginación
                    let paginationHtml = '';
                    for (let i = 1; i <= totalPages; i++) {
                        paginationHtml += `<li class="page-item ${i == page ? 'active' : ''}">
                            <a class="page-link" href="#" onclick="fetchConcesiones('${search}', ${i}); return false;">${i}</a>
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
                fetchConcesiones(searchInput.value, 1);
            });

            // Inicializar la primera carga de concesiones
            fetchConcesiones('', 1);
        });
    </script>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="../dashboard.php">Admin Dashboard</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="../elements/peliculas.php">Películas</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="../elements/cines_salasyfunciones.php">Cines, Salas y Funciones</a>
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
        <h2 class="mt-5">Gestionar Concesiones</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form action="concesiones.php" method="post" class="mb-4">
            <input type="hidden" name="id" value="<?php echo $concesionEdit['ID'] ?? ''; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="action" value="save">

            <div class="form-group">
                <label for="nombre_producto">Nombre del Producto</label>
                <input type="text" class="form-control" id="nombre_producto" name="nombre_producto" value="<?php echo htmlspecialchars($concesionEdit['NombreProducto'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <div class="form-group">
                <label for="descripcion">Descripción</label>
                <input type="text" class="form-control" id="descripcion" name="descripcion" value="<?php echo htmlspecialchars($concesionEdit['Descripcion'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <div class="form-group">
                <label for="precio">Precio</label>
                <input type="number" step="0.01" class="form-control" id="precio" name="precio" value="<?php echo htmlspecialchars($concesionEdit['Precio'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <div class="form-group">
                <label for="categoria">Categoría</label>
                <input type="text" class="form-control" id="categoria" name="categoria" value="<?php echo htmlspecialchars($concesionEdit['Categoria'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <button type="submit" class="btn btn-primary">Guardar</button>
        </form>

        <form method="get" action="concesiones.php" class="mb-4">
            <div class="input-group">
                <input type="text" class="form-control" name="search" placeholder="Buscar por nombre, descripción o categoría">
                <div class="input-group-append">
                    <button class="btn btn-outline-secondary" type="submit">Buscar</button>
                </div>
            </div>
        </form>

        <h3>Lista de Concesiones</h3>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Nombre del Producto</th>
                    <th>Descripción</th>
                    <th>Precio</th>
                    <th>Categoría</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <!-- Los datos se llenarán a través de AJAX -->
            </tbody>
        </table>

        <nav aria-label="Page navigation">
            <ul class="pagination">
                <!-- La paginación se llenará a través de AJAX -->
            </ul>
        </nav>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
