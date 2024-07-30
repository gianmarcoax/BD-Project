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

$salas = [];
$funciones = [];

$editMode = false;
$funcionEdit = null;

$items_per_page = 6;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($page - 1) * $items_per_page;

// Establecer la codificación a UTF-8
$conn->set_charset("utf8mb4");

// Obtener salas si se seleccionó un cine
if (isset($_GET['cine_id'])) {
    $cine_id = $_GET['cine_id'];
    $stmt = $conn->prepare("SELECT * FROM Salas WHERE Cine_ID = ?");
    $stmt->bind_param("i", $cine_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $salas = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
}

// Obtener funciones si se seleccionó una sala
if (isset($_GET['sala_id'])) {
    $sala_id = $_GET['sala_id'];
    $stmt = $conn->prepare("SELECT f.*, p.Titulo AS PeliculaTitulo, s.NumeroSala, c.Nombre AS CineNombre 
                            FROM Funciones f 
                            INNER JOIN Peliculas p ON f.Pelicula_ID = p.ID 
                            INNER JOIN Salas s ON f.Sala_ID = s.ID 
                            INNER JOIN Cines c ON f.Cine_ID = c.ID 
                            WHERE f.Sala_ID = ? 
                            LIMIT ? OFFSET ?");
    $stmt->bind_param("iii", $sala_id, $items_per_page, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    $funciones = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    $stmt = $conn->prepare("SELECT COUNT(*) FROM Funciones WHERE Sala_ID = ?");
    $stmt->bind_param("i", $sala_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $total_items = $result->fetch_row()[0];
    $total_pages = ceil($total_items / $items_per_page);
    $stmt->close();
} else {
    $total_pages = 1; // Definir $total_pages como mínimo de 1 si no hay sala seleccionada
}

// Obtener datos de función para editar
if (isset($_GET['edit'])) {
    $editMode = true;
    $id = $_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM Funciones WHERE ID = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $funcionEdit = $result->fetch_assoc();
    $stmt->close();
}

// Manejo de operaciones CRUD
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $cine_id = $_POST['cine_id'] ?? '';
    $sala_id = $_POST['sala_id'] ?? '';
    $pelicula_id = $_POST['pelicula_id'] ?? '';
    $fecha_funcion = $_POST['fecha_funcion'] ?? '';
    $hora_inicio = $_POST['hora_inicio'] ?? '';

    $validationResult = validateFuncion($cine_id, $sala_id, $fecha_funcion, $hora_inicio);
    if ($validationResult !== true) {
        $error = $validationResult;
    } else {
        if (isset($_POST['id']) && !empty($_POST['id'])) {
            // Actualizar función existente
            $id = $_POST['id'];
            $stmt = $conn->prepare("UPDATE Funciones SET Pelicula_ID = ?, Sala_ID = ?, Cine_ID = ?, FechaFuncion = ?, HoraInicio = ? WHERE ID = ?");
            $stmt->bind_param("iiissi", $pelicula_id, $sala_id, $cine_id, $fecha_funcion, $hora_inicio, $id);
        } else {
            // Insertar nueva función
            $stmt = $conn->prepare("INSERT INTO Funciones (Pelicula_ID, Sala_ID, Cine_ID, FechaFuncion, HoraInicio) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("iiiss", $pelicula_id, $sala_id, $cine_id, $fecha_funcion, $hora_inicio);
        }

        if ($stmt->execute()) {
            header("Location: cines_salasyfunciones.php?cine_id=$cine_id&sala_id=$sala_id");
            exit();
        } else {
            $error = "Error al guardar la función: " . $stmt->error;
        }
        $stmt->close();
    }
}

// Manejo de eliminación
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM Funciones WHERE ID = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header("Location: cines_salasyfunciones.php?cine_id=$cine_id&sala_id=$sala_id");
        exit();
    } else {
        $error = "Error al eliminar la función: " . $stmt->error;
    }
    $stmt->close();
}

// Obtener todas las películas
$result = $conn->query("SELECT * FROM Peliculas");
$peliculas = $result->fetch_all(MYSQLI_ASSOC);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Cines, Salas y Funciones</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script>
        function changeCine() {
            document.getElementById('cineForm').submit();
        }

        function changeSala() {
            document.getElementById('salaForm').submit();
        }
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
        <h2 class="mt-5">Gestionar Cines, Salas y Funciones</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form id="cineForm" method="get" action="cines_salasyfunciones.php" class="mb-4">
            <div class="form-group">
                <label for="cine_id">Cine</label>
                <select class="form-control" id="cine_id" name="cine_id" onchange="changeCine()" required>
                    <option value="">Seleccione un cine</option>
                    <?php foreach ($cines as $cine): ?>
                        <option value="<?php echo $cine['ID']; ?>" <?php echo (isset($cine_id) && $cine_id == $cine['ID']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($cine['Nombre']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
        </form>

        <?php if (!empty($cine_id)): ?>
            <form id="salaForm" method="get" action="cines_salasyfunciones.php" class="mb-4">
                <input type="hidden" name="cine_id" value="<?php echo $cine_id; ?>">
                <div class="form-group">
                    <label for="sala_id">Sala</label>
                    <select class="form-control" id="sala_id" name="sala_id" onchange="changeSala()" required>
                        <option value="">Seleccione una sala</option>
                        <?php foreach ($salas as $sala): ?>
                            <option value="<?php echo $sala['ID']; ?>" <?php echo (isset($sala_id) && $sala_id == $sala['ID']) ? 'selected' : ''; ?>>
                                Sala <?php echo htmlspecialchars($sala['NumeroSala']); ?> (<?php echo htmlspecialchars($sala['TipoSala']); ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </form>
        <?php endif; ?>

        <form action="cines_salasyfunciones.php?cine_id=<?php echo $cine_id ?? ''; ?>&sala_id=<?php echo $sala_id ?? ''; ?>" method="post" class="mb-4">
            <input type="hidden" name="id" value="<?php echo $funcionEdit['ID'] ?? ''; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="cine_id" value="<?php echo $cine_id ?? ''; ?>">
            <input type="hidden" name="sala_id" value="<?php echo $sala_id ?? ''; ?>">
            <input type="hidden" name="action" value="save">

            <div class="form-group">
                <label for="pelicula_id">Película</label>
                <select class="form-control" id="pelicula_id" name="pelicula_id" required <?php echo empty($cine_id) || empty($sala_id) ? 'disabled' : ''; ?>>
                    <option value="">Seleccione una película</option>
                    <?php foreach ($peliculas as $pelicula): ?>
                        <option value="<?php echo $pelicula['ID']; ?>" <?php echo (isset($funcionEdit['Pelicula_ID']) && $funcionEdit['Pelicula_ID'] == $pelicula['ID']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($pelicula['Titulo']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="fecha_funcion">Fecha de Función</label>
                <input type="date" class="form-control" id="fecha_funcion" name="fecha_funcion" value="<?php echo $funcionEdit['FechaFuncion'] ?? ''; ?>" required <?php echo empty($cine_id) || empty($sala_id) ? 'disabled' : ''; ?>>
            </div>

            <div class="form-group">
                <label for="hora_inicio">Hora de Inicio</label>
                <input type="time" class="form-control" id="hora_inicio" name="hora_inicio" value="<?php echo $funcionEdit['HoraInicio'] ?? ''; ?>" required <?php echo empty($cine_id) || empty($sala_id) ? 'disabled' : ''; ?>>
            </div>

            <button type="submit" class="btn btn-primary" <?php echo empty($cine_id) || empty($sala_id) ? 'disabled' : ''; ?>>Guardar</button>
        </form>

        <h3>Funciones de la Sala Seleccionada</h3>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Película</th>
                    <th>Fecha de Función</th>
                    <th>Hora de Inicio</th>
                    <th>Sala</th>
                    <th>Cine</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($funciones as $funcion): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($funcion['ID']); ?></td>
                        <td><?php echo htmlspecialchars($funcion['PeliculaTitulo']); ?></td>
                        <td><?php echo htmlspecialchars($funcion['FechaFuncion']); ?></td>
                        <td><?php echo htmlspecialchars($funcion['HoraInicio']); ?></td>
                        <td><?php echo htmlspecialchars($funcion['NumeroSala']); ?></td>
                        <td><?php echo htmlspecialchars($funcion['CineNombre']); ?></td>
                        <td>
                            <a href="cines_salasyfunciones.php?cine_id=<?php echo $cine_id ?? ''; ?>&sala_id=<?php echo $sala_id ?? ''; ?>&edit=<?php echo $funcion['ID']; ?>" class="btn btn-sm btn-warning">Editar</a>
                            <a href="cines_salasyfunciones.php?cine_id=<?php echo $cine_id ?? ''; ?>&sala_id=<?php echo $sala_id ?? ''; ?>&delete=<?php echo $funcion['ID']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar esta función?');">Eliminar</a>
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
                        <a class="page-link" href="cines_salasyfunciones.php?cine_id=<?php echo $cine_id ?? ''; ?>&sala_id=<?php echo $sala_id ?? ''; ?>&page=<?php echo $i; ?>"><?php echo $i; ?></a>
                    </li>
                <?php endfor; ?>
            </ul>
        </nav>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
