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

// Obtener promociones
$result = $conn->query("SELECT * FROM Promociones LIMIT $items_per_page OFFSET $offset");
$promociones = $result->fetch_all(MYSQLI_ASSOC);

// Obtener el total de promociones para la paginación
$result = $conn->query("SELECT COUNT(*) FROM Promociones");
$total_items = $result->fetch_row()[0];
$total_pages = ceil($total_items / $items_per_page);

$editMode = false;
$promocionEdit = null;

// Obtener datos de promoción para editar
if (isset($_GET['edit'])) {
    $editMode = true;
    $id = $_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM Promociones WHERE ID = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $promocionEdit = $result->fetch_assoc();
    $stmt->close();
}

// Manejo de operaciones CRUD para promociones
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $nombre_promocion = $_POST['nombre_promocion'] ?? '';
    $descripcion = $_POST['descripcion'] ?? '';
    $descuento = $_POST['descuento'] ?? '';
    $fecha_inicio = $_POST['fecha_inicio'] ?? '';
    $fecha_fin = $_POST['fecha_fin'] ?? '';

    // Aquí deberías validar los datos, por ejemplo:
    if (empty($nombre_promocion) || empty($descripcion) || empty($descuento) || empty($fecha_inicio) || empty($fecha_fin)) {
        $error = "Todos los campos son obligatorios.";
    } else {
        if (isset($_POST['id']) && !empty($_POST['id'])) {
            // Actualizar promoción existente
            $id = $_POST['id'];
            $stmt = $conn->prepare("UPDATE Promociones SET NombrePromocion = ?, Descripcion = ?, Descuento = ?, FechaInicio = ?, FechaFin = ? WHERE ID = ?");
            $stmt->bind_param("ssdsii", $nombre_promocion, $descripcion, $descuento, $fecha_inicio, $fecha_fin, $id);
        } else {
            // Insertar nueva promoción
            $stmt = $conn->prepare("INSERT INTO Promociones (NombrePromocion, Descripcion, Descuento, FechaInicio, FechaFin) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("ssdii", $nombre_promocion, $descripcion, $descuento, $fecha_inicio, $fecha_fin);
        }

        if ($stmt->execute()) {
            header("Location: promociones.php");
            exit();
        } else {
            $error = "Error al guardar la promoción: " . $stmt->error;
        }
        $stmt->close();
    }
}

// Manejo de eliminación
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM Promociones WHERE ID = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header("Location: promociones.php");
        exit();
    } else {
        $error = "Error al eliminar la promoción: " . $stmt->error;
    }
    $stmt->close();
}

// Obtener todas las películas
$result = $conn->query("SELECT * FROM Peliculas");
$peliculas = $result->fetch_all(MYSQLI_ASSOC);

// Obtener todas las concesiones
$result = $conn->query("SELECT * FROM Concesiones");
$concesiones = $result->fetch_all(MYSQLI_ASSOC);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Promociones</title>
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
        <h2 class="mt-5">Gestionar Promociones</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form action="promociones.php" method="post" class="mb-4">
            <input type="hidden" name="id" value="<?php echo $promocionEdit['ID'] ?? ''; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="action" value="save">

            <div class="form-group">
                <label for="nombre_promocion">Nombre de la Promoción</label>
                <input type="text" class="form-control" id="nombre_promocion" name="nombre_promocion" value="<?php echo $promocionEdit['NombrePromocion'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="descripcion">Descripción</label>
                <input type="text" class="form-control" id="descripcion" name="descripcion" value="<?php echo $promocionEdit['Descripcion'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="descuento">Descuento (%)</label>
                <input type="number" step="0.01" class="form-control" id="descuento" name="descuento" value="<?php echo $promocionEdit['Descuento'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="fecha_inicio">Fecha de Inicio</label>
                <input type="date" class="form-control" id="fecha_inicio" name="fecha_inicio" value="<?php echo $promocionEdit['FechaInicio'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="fecha_fin">Fecha de Fin</label>
                <input type="date" class="form-control" id="fecha_fin" name="fecha_fin" value="<?php echo $promocionEdit['FechaFin'] ?? ''; ?>" required>
            </div>

            <button type="submit" class="btn btn-primary">Guardar</button>
        </form>

        <h3>Lista de Promociones</h3>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Nombre de la Promoción</th>
                    <th>Descripción</th>
                    <th>Descuento</th>
                    <th>Fecha de Inicio</th>
                    <th>Fecha de Fin</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($promociones as $promocion): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($promocion['ID']); ?></td>
                        <td><?php echo htmlspecialchars($promocion['NombrePromocion']); ?></td>
                        <td><?php echo htmlspecialchars($promocion['Descripcion']); ?></td>
                        <td><?php echo htmlspecialchars($promocion['Descuento']); ?></td>
                        <td><?php echo htmlspecialchars($promocion['FechaInicio']); ?></td>
                        <td><?php echo htmlspecialchars($promocion['FechaFin']); ?></td>
                        <td>
                            <a href="promociones.php?edit=<?php echo $promocion['ID']; ?>" class="btn btn-sm btn-warning">Editar</a>
                            <a href="promociones.php?delete=<?php echo $promocion['ID']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar esta promoción?');">Eliminar</a>
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
                        <a class="page-link" href="promociones.php?page=<?php echo $i; ?>"><?php echo $i; ?></a>
                    </li>
                <?php endfor; ?>
            </ul>
        </nav>

        <!-- Gestión de Películas y Concesiones en Promociones -->
        <?php if ($editMode): ?>
            <h3>Gestionar Películas en la Promoción</h3>
            <form action="promociones.php" method="post" class="mb-4">
                <input type="hidden" name="promocion_id" value="<?php echo $promocionEdit['ID']; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="action" value="add_pelicula">

                <div class="form-group">
                    <label for="pelicula_id">Película</label>
                    <select class="form-control" id="pelicula_id" name="pelicula_id" required>
                        <option value="">Seleccione una película</option>
                        <?php foreach ($peliculas as $pelicula): ?>
                            <option value="<?php echo $pelicula['ID']; ?>"><?php echo htmlspecialchars($pelicula['Titulo']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <button type="submit" class="btn btn-primary">Añadir Película a la Promoción</button>
            </form>

            <h3>Películas en la Promoción</h3>
            <?php
            // Obtener películas en la promoción
            $stmt = $conn->prepare("SELECT pp.ID, p.Titulo FROM PeliculasPromociones pp INNER JOIN Peliculas p ON pp.Pelicula_ID = p.ID WHERE pp.Promocion_ID = ?");
            $stmt->bind_param("i", $promocionEdit['ID']);
            $stmt->execute();
            $result = $stmt->get_result();
            $peliculasPromocion = $result->fetch_all(MYSQLI_ASSOC);
            $stmt->close();
            ?>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Título</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($peliculasPromocion as $pelicula): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($pelicula['ID']); ?></td>
                            <td><?php echo htmlspecialchars($pelicula['Titulo']); ?></td>
                            <td>
                                <a href="promociones.php?remove_pelicula=<?php echo $pelicula['ID']; ?>&promocion_id=<?php echo $promocionEdit['ID']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar esta película de la promoción?');">Eliminar</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <h3>Gestionar Concesiones en la Promoción</h3>
            <form action="promociones.php" method="post" class="mb-4">
                <input type="hidden" name="promocion_id" value="<?php echo $promocionEdit['ID']; ?>">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="action" value="add_concesion">

                <div class="form-group">
                    <label for="concesion_id">Concesión</label>
                    <select class="form-control" id="concesion_id" name="concesion_id" required>
                        <option value="">Seleccione una concesión</option>
                        <?php foreach ($concesiones as $concesion): ?>
                            <option value="<?php echo $concesion['ID']; ?>"><?php echo htmlspecialchars($concesion['NombreProducto']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <button type="submit" class="btn btn-primary">Añadir Concesión a la Promoción</button>
            </form>

            <h3>Concesiones en la Promoción</h3>
            <?php
            // Obtener concesiones en la promoción
            $stmt = $conn->prepare("SELECT cp.ID, c.NombreProducto FROM ConcesionesPromociones cp INNER JOIN Concesiones c ON cp.Concesion_ID = c.ID WHERE cp.Promocion_ID = ?");
            $stmt->bind_param("i", $promocionEdit['ID']);
            $stmt->execute();
            $result = $stmt->get_result();
            $concesionesPromocion = $result->fetch_all(MYSQLI_ASSOC);
            $stmt->close();
            ?>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Nombre Producto</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($concesionesPromocion as $concesion): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($concesion['ID']); ?></td>
                            <td><?php echo htmlspecialchars($concesion['NombreProducto']); ?></td>
                            <td>
                                <a href="promociones.php?remove_concesion=<?php echo $concesion['ID']; ?>&promocion_id=<?php echo $promocionEdit['ID']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar esta concesión de la promoción?');">Eliminar</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</body>
</html>
