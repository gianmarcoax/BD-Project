<?php
session_start();
require_once __DIR__ . '/../../../middlewares/auth.php';
require_once __DIR__ . '/../../../helpers/validation.php';
require_once __DIR__ . '/../../../../config/db_connect.php';

requireAdmin();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$clientes = [];
$editMode = false;
$clienteEdit = null;

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

    $stmt = $conn->prepare("SELECT * FROM Clientes WHERE Nombre LIKE CONCAT('%',?,'%') OR CorreoElectronico LIKE CONCAT('%',?,'%') OR Telefono LIKE CONCAT('%',?,'%') LIMIT ? OFFSET ?");
    $stmt->bind_param("sssii", $search, $search, $search, $items_per_page, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    $clientes = $result->fetch_all(MYSQLI_ASSOC);

    // Escapar datos de usuario para evitar XSS
    foreach ($clientes as &$cliente) {
        foreach ($cliente as &$value) {
            $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }

    // Obtener el número total de clientes para la paginación
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM Clientes WHERE Nombre LIKE CONCAT('%',?,'%') OR CorreoElectronico LIKE CONCAT('%',?,'%') OR Telefono LIKE CONCAT('%',?,'%')");
    $stmt->bind_param("sss", $search, $search, $search);
    $stmt->execute();
    $result = $stmt->get_result();
    $totalClientes = $result->fetch_assoc()['count'];
    $totalPages = ceil($totalClientes / $items_per_page);

    echo json_encode(['clientes' => $clientes, 'totalPages' => $totalPages]);
    exit();
}

// Obtener datos de cliente para editar
if (isset($_GET['edit'])) {
    $editMode = true;
    $id = $_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM Clientes WHERE ID = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $clienteEdit = $result->fetch_assoc();
}

// Manejo de operaciones CRUD
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $nombre = $_POST['nombre'] ?? '';
    $correo = $_POST['correo'] ?? '';
    $telefono = $_POST['telefono'] ?? '';

    if (empty($nombre) || empty($correo) || empty($telefono)) {
        $error = 'Todos los campos son obligatorios.';
    } elseif (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
        $error = 'Correo electrónico no válido.';
    } else {
        if (isset($_POST['id']) && !empty($_POST['id'])) {
            // Actualizar cliente existente
            $id = $_POST['id'];
            $stmt = $conn->prepare("UPDATE Clientes SET Nombre = ?, CorreoElectronico = ?, Telefono = ? WHERE ID = ?");
            $stmt->bind_param("sssi", $nombre, $correo, $telefono, $id);
        } else {
            // Insertar nuevo cliente
            $stmt = $conn->prepare("INSERT INTO Clientes (Nombre, CorreoElectronico, Telefono) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $nombre, $correo, $telefono);
        }

        if ($stmt->execute()) {
            header("Location: clientes.php");
            exit();
        } else {
            $error = "Error al guardar el cliente: " . $stmt->error;
        }
    }
}

// Manejo de eliminación
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM Clientes WHERE ID = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header("Location: clientes.php");
        exit();
    } else {
        $error = "Error al eliminar el cliente: " . $stmt->error;
    }
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Clientes</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script>
        function fetchClientes(search, page) {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', 'clientes.php?ajax=1&search=' + encodeURIComponent(search) + '&page=' + page, true);
            xhr.onload = function() {
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText);
                    const clientes = response.clientes;
                    const totalPages = response.totalPages;

                    let html = '';
                    for (let cliente of clientes) {
                        html += `<tr>
                            <td>${cliente.ID}</td>
                            <td>${cliente.Nombre}</td>
                            <td>${cliente.CorreoElectronico}</td>
                            <td>${cliente.Telefono}</td>
                            <td>
                                <a href="clientes.php?edit=${cliente.ID}" class="btn btn-sm btn-warning">Editar</a>
                                <a href="clientes.php?delete=${cliente.ID}" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar este cliente?');">Eliminar</a>
                            </td>
                        </tr>`;
                    }
                    document.querySelector('tbody').innerHTML = html;

                    // Actualizar la paginación
                    let paginationHtml = '';
                    for (let i = 1; i <= totalPages; i++) {
                        paginationHtml += `<li class="page-item ${i == page ? 'active' : ''}">
                            <a class="page-link" href="#" onclick="fetchClientes('${search}', ${i}); return false;">${i}</a>
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
                fetchClientes(searchInput.value, 1);
            });

            // Inicializar la primera carga de clientes
            fetchClientes('', 1);
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
        <h2 class="mt-5">Gestionar Clientes</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <form action="clientes.php" method="post" class="mb-4">
            <input type="hidden" name="id" value="<?php echo htmlspecialchars($clienteEdit['ID'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="action" value="save">

            <div class="form-group">
                <label for="nombre">Nombre</label>
                <input type="text" class="form-control" id="nombre" name="nombre" value="<?php echo htmlspecialchars($clienteEdit['Nombre'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <div class="form-group">
                <label for="correo">Correo Electrónico</label>
                <input type="email" class="form-control" id="correo" name="correo" value="<?php echo htmlspecialchars($clienteEdit['CorreoElectronico'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <div class="form-group">
                <label for="telefono">Teléfono</label>
                <input type="text" class="form-control" id="telefono" name="telefono" value="<?php echo htmlspecialchars($clienteEdit['Telefono'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <button type="submit" class="btn btn-primary">Guardar</button>
        </form>

        <form method="get" action="clientes.php" class="mb-4">
            <div class="input-group">
                <input type="text" class="form-control" name="search" placeholder="Buscar por nombre, correo o teléfono">
                <div class="input-group-append">
                    <button class="btn btn-outline-secondary" type="submit">Buscar</button>
                </div>
            </div>
        </form>

        <h3>Lista de Clientes</h3>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Nombre</th>
                    <th>Correo Electrónico</th>
                    <th>Teléfono</th>
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
