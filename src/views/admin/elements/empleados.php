<?php
session_start();
require_once __DIR__ . '/../../../middlewares/auth.php';
require_once __DIR__ . '/../../../helpers/validation.php';
require_once __DIR__ . '/../../../../config/db_connect.php';

requireAdmin();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Obtener cines
$result = $conn->query("SELECT * FROM Cines");
$cines = $result->fetch_all(MYSQLI_ASSOC);

$editMode = false;
$empleadoEdit = null;

$items_per_page = 6;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($page - 1) * $items_per_page;

// Obtener empleados con paginación
$stmt = $conn->prepare("SELECT e.*, c.Nombre AS CineNombre 
                        FROM Empleados e 
                        INNER JOIN Cines c ON e.Cine_ID = c.ID 
                        LIMIT ? OFFSET ?");
$stmt->bind_param("ii", $items_per_page, $offset);
$stmt->execute();
$result = $stmt->get_result();
$empleados = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();

$stmt = $conn->prepare("SELECT COUNT(*) FROM Empleados");
$stmt->execute();
$result = $stmt->get_result();
$total_items = $result->fetch_row()[0];
$total_pages = ceil($total_items / $items_per_page);
$stmt->close();

// Obtener datos de empleado para editar
if (isset($_GET['edit'])) {
    $editMode = true;
    $id = $_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM Empleados WHERE ID = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $empleadoEdit = $result->fetch_assoc();
    $stmt->close();
}

// Manejo de operaciones CRUD
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $nombre = $_POST['nombre'] ?? '';
    $apellido = $_POST['apellido'] ?? '';
    $cargo = $_POST['cargo'] ?? '';
    $cine_id = $_POST['cine_id'] ?? '';

    if (isset($_POST['id']) && !empty($_POST['id'])) {
        // Actualizar empleado existente
        $id = $_POST['id'];
        $stmt = $conn->prepare("UPDATE Empleados SET Nombre = ?, Apellido = ?, Cargo = ?, Cine_ID = ? WHERE ID = ?");
        $stmt->bind_param("sssii", $nombre, $apellido, $cargo, $cine_id, $id);
    } else {
        // Insertar nuevo empleado
        $stmt = $conn->prepare("INSERT INTO Empleados (Nombre, Apellido, Cargo, Cine_ID) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("sssi", $nombre, $apellido, $cargo, $cine_id);
    }

    if ($stmt->execute()) {
        header("Location: empleados.php");
        exit();
    } else {
        $error = "Error al guardar el empleado: " . $stmt->error;
    }
    $stmt->close();
}

// Manejo de eliminación
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM Empleados WHERE ID = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header("Location: empleados.php");
        exit();
    } else {
        $error = "Error al eliminar el empleado: " . $stmt->error;
    }
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Empleados</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
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
        <h2 class="mt-5">Gestionar Empleados</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form action="empleados.php" method="post" class="mb-4">
            <input type="hidden" name="id" value="<?php echo $empleadoEdit['ID'] ?? ''; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="action" value="save">

            <div class="form-group">
                <label for="nombre">Nombre</label>
                <input type="text" class="form-control" id="nombre" name="nombre" value="<?php echo $empleadoEdit['Nombre'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="apellido">Apellido</label>
                <input type="text" class="form-control" id="apellido" name="apellido" value="<?php echo $empleadoEdit['Apellido'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="cargo">Cargo</label>
                <input type="text" class="form-control" id="cargo" name="cargo" value="<?php echo $empleadoEdit['Cargo'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="cine_id">Cine</label>
                <select class="form-control" id="cine_id" name="cine_id" required>
                    <option value="">Seleccione un cine</option>
                    <?php foreach ($cines as $cine): ?>
                        <option value="<?php echo $cine['ID']; ?>" <?php echo (isset($empleadoEdit['Cine_ID']) && $empleadoEdit['Cine_ID'] == $cine['ID']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($cine['Nombre']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <button type="submit" class="btn btn-primary">Guardar</button>
        </form>

        <h3>Empleados Registrados</h3>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Nombre</th>
                    <th>Apellido</th>
                    <th>Cargo</th>
                    <th>Cine</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($empleados as $empleado): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($empleado['ID']); ?></td>
                        <td><?php echo htmlspecialchars($empleado['Nombre']); ?></td>
                        <td><?php echo htmlspecialchars($empleado['Apellido']); ?></td>
                        <td><?php echo htmlspecialchars($empleado['Cargo']); ?></td>
                        <td><?php echo htmlspecialchars($empleado['CineNombre']); ?></td>
                        <td>
                            <a href="empleados.php?edit=<?php echo $empleado['ID']; ?>" class="btn btn-sm btn-warning">Editar</a>
                            <a href="empleados.php?delete=<?php echo $empleado['ID']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar este empleado?');">Eliminar</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Paginación -->
        <nav aria-label="Page navigation">
            <ul class="pagination">
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <li class="page-item <?php echo ($i == $page) ? 'active' : ''; ?>">
                        <a class="page-link" href="empleados.php?page=<?php echo $i; ?>"><?php echo $i; ?></a>
                    </li>
                <?php endfor; ?>
            </ul>
        </nav>
    </div>
</body>
</html>
