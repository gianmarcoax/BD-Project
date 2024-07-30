<?php
session_start();
require_once __DIR__ . '/../../../middlewares/auth.php';
require_once __DIR__ . '/../../../helpers/validation.php';
require_once __DIR__ . '/../../../../config/db_connect.php';

requireAdmin();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$boletos = [];
$funciones = [];
$clientes = [];
$editMode = false;
$boletoEdit = null;

$items_per_page = 6;
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($page - 1) * $items_per_page;

// Establecer la codificación a UTF-8
$conn->set_charset("utf8mb4");

// Obtener todas las funciones con detalles adicionales
$result = $conn->query("SELECT f.ID, p.Titulo, f.FechaFuncion, f.HoraInicio, s.NumeroSala, c.Nombre AS CineNombre FROM Funciones f INNER JOIN Peliculas p ON f.Pelicula_ID = p.ID INNER JOIN Salas s ON f.Sala_ID = s.ID INNER JOIN Cines c ON f.Cine_ID = c.ID");
$funciones = $result->fetch_all(MYSQLI_ASSOC);

// Obtener todos los clientes
$result = $conn->query("SELECT * FROM Clientes");
$clientes = $result->fetch_all(MYSQLI_ASSOC);

// Obtener todos los boletos con paginación
$stmt = $conn->prepare("SELECT b.*, c.Nombre AS ClienteNombre, f.FechaFuncion, f.HoraInicio, p.Titulo AS PeliculaTitulo, s.NumeroSala, cn.Nombre AS CineNombre FROM Boletos b INNER JOIN Clientes c ON b.Cliente_ID = c.ID INNER JOIN Funciones f ON b.Funcion_ID = f.ID INNER JOIN Peliculas p ON f.Pelicula_ID = p.ID INNER JOIN Salas s ON f.Sala_ID = s.ID INNER JOIN Cines cn ON f.Cine_ID = cn.ID LIMIT ? OFFSET ?");
$stmt->bind_param("ii", $items_per_page, $offset);
$stmt->execute();
$result = $stmt->get_result();
$boletos = $result->fetch_all(MYSQLI_ASSOC);

$stmt = $conn->prepare("SELECT COUNT(*) FROM Boletos");
$stmt->execute();
$result = $stmt->get_result();
$total_items = $result->fetch_row()[0];
$total_pages = ceil($total_items / $items_per_page);

// Obtener datos de boleto para editar
if (isset($_GET['edit'])) {
    $editMode = true;
    $id = $_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM Boletos WHERE ID = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $boletoEdit = $result->fetch_assoc();
}

// Manejo de operaciones CRUD
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token');
    }

    $funcion_id = $_POST['funcion_id'] ?? '';
    $cliente_id = $_POST['cliente_id'] ?? '';
    $numero = $_POST['numero'] ?? '';
    $precio = $_POST['precio'] ?? '';
    $tipo_asiento = $_POST['tipo_asiento'] ?? '';
    $fecha_hora = $_POST['fecha_hora'] ?? '';
    $numero_asiento = $_POST['numero_asiento'] ?? '';

    if (empty($funcion_id) || empty($cliente_id) || empty($numero) || empty($precio) || empty($tipo_asiento) || empty($fecha_hora) || empty($numero_asiento)) {
        $error = 'Todos los campos son obligatorios.';
    } else {
        if (isset($_POST['id']) && !empty($_POST['id'])) {
            // Actualizar boleto existente
            $id = $_POST['id'];
            $stmt = $conn->prepare("UPDATE Boletos SET Funcion_ID = ?, Cliente_ID = ?, Numero = ?, Precio = ?, TipoAsiento = ?, FechaHora = ?, NumeroAsiento = ? WHERE ID = ?");
            $stmt->bind_param("iiissssi", $funcion_id, $cliente_id, $numero, $precio, $tipo_asiento, $fecha_hora, $numero_asiento, $id);
        } else {
            // Insertar nuevo boleto
            $stmt = $conn->prepare("INSERT INTO Boletos (Funcion_ID, Cliente_ID, Numero, Precio, TipoAsiento, FechaHora, NumeroAsiento) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("iiisssi", $funcion_id, $cliente_id, $numero, $precio, $tipo_asiento, $fecha_hora, $numero_asiento);
        }

        if ($stmt->execute()) {
            header("Location: boletos.php?page=$page");
            exit();
        } else {
            $error = "Error al guardar el boleto: " . $stmt->error;
        }
    }
}

// Manejo de eliminación
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $conn->prepare("DELETE FROM Boletos WHERE ID = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header("Location: boletos.php?page=$page");
        exit();
    } else {
        $error = "Error al eliminar el boleto: " . $stmt->error;
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Boletos</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
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
        <h2 class="mt-5">Gestionar Boletos</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form action="boletos.php" method="post" class="mb-4">
            <input type="hidden" name="id" value="<?php echo $boletoEdit['ID'] ?? ''; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="action" value="save">

            <div class="form-group">
                <label for="funcion_id">Función</label>
                <select class="form-control" id="funcion_id" name="funcion_id" required>
                    <option value="">Seleccione una función</option>
                    <?php foreach ($funciones as $funcion): ?>
                        <option value="<?php echo $funcion['ID']; ?>" <?php echo (isset($boletoEdit['Funcion_ID']) && $boletoEdit['Funcion_ID'] == $funcion['ID']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($funcion['Titulo']) . " - " . htmlspecialchars($funcion['FechaFuncion']) . " " . htmlspecialchars($funcion['HoraInicio']) . " - Sala " . htmlspecialchars($funcion['NumeroSala']) . " (" . htmlspecialchars($funcion['CineNombre']) . ")"; ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="cliente_id">Cliente</label>
                <select class="form-control" id="cliente_id" name="cliente_id" required>
                    <option value="">Seleccione un cliente</option>
                    <?php foreach ($clientes as $cliente): ?>
                        <option value="<?php echo $cliente['ID']; ?>" <?php echo (isset($boletoEdit['Cliente_ID']) && $boletoEdit['Cliente_ID'] == $cliente['ID']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($cliente['Nombre']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="form-group">
                <label for="numero">Número de Boleto</label>
                <input type="number" class="form-control" id="numero" name="numero" value="<?php echo $boletoEdit['Numero'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="precio">Precio</label>
                <input type="text" class="form-control" id="precio" name="precio" value="<?php echo $boletoEdit['Precio'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="tipo_asiento">Tipo de Asiento</label>
                <input type="text" class="form-control" id="tipo_asiento" name="tipo_asiento" value="<?php echo $boletoEdit['TipoAsiento'] ?? ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="fecha_hora">Fecha y Hora</label>
                <input type="datetime-local" class="form-control" id="fecha_hora" name="fecha_hora" value="<?php echo isset($boletoEdit['FechaHora']) ? date('Y-m-d\TH:i', strtotime($boletoEdit['FechaHora'])) : ''; ?>" required>
            </div>

            <div class="form-group">
                <label for="numero_asiento">Número de Asiento</label>
                <input type="number" class="form-control" id="numero_asiento" name="numero_asiento" value="<?php echo $boletoEdit['NumeroAsiento'] ?? ''; ?>" required>
            </div>

            <button type="submit" class="btn btn-primary">Guardar</button>
        </form>

        <h3>Lista de Boletos</h3>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Función</th>
                    <th>Cliente</th>
                    <th>Número de Boleto</th>
                    <th>Precio</th>
                    <th>Tipo de Asiento</th>
                    <th>Fecha y Hora</th>
                    <th>Número de Asiento</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody> 
                <?php foreach ($boletos as $boleto): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($boleto['ID']); ?></td>
                        <td><?php echo htmlspecialchars($boleto['PeliculaTitulo']) . " - " . htmlspecialchars($boleto['FechaFuncion']) . " " . htmlspecialchars($boleto['HoraInicio']) . " - Sala " . htmlspecialchars($boleto['NumeroSala']) . " (" . htmlspecialchars($boleto['CineNombre']) . ")"; ?></td>
                        <td><?php echo htmlspecialchars($boleto['ClienteNombre']); ?></td>
                        <td><?php echo htmlspecialchars($boleto['Numero']); ?></td>
                        <td><?php echo htmlspecialchars($boleto['Precio']); ?></td>
                        <td><?php echo htmlspecialchars($boleto['TipoAsiento']); ?></td>
                        <td><?php echo htmlspecialchars($boleto['FechaHora']); ?></td>
                        <td><?php echo htmlspecialchars($boleto['NumeroAsiento']); ?></td>
                        <td>
                            <a href="boletos.php?edit=<?php echo $boleto['ID']; ?>" class="btn btn-sm btn-warning">Editar</a>
                            <a href="boletos.php?delete=<?php echo $boleto['ID']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('¿Estás seguro de eliminar este boleto?');">Eliminar</a>
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
                        <a class="page-link" href="boletos.php?page=<?php echo $i; ?>"><?php echo $i; ?></a>
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
