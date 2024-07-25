<?php
session_start();
require_once 'src/middlewares/auth.php';
require_once 'config/db_connect.php';

if (!isLoggedIn()) {
    header('Location: auth/login.php');
    exit();
}

if (!isset($_GET['pelicula_id'])) {
    header('Location: index.php');
    exit();
}

$pelicula_id = $_GET['pelicula_id'];
$cliente_id = $_SESSION['user_id'];

// Verificar si el cliente está en la base de datos
$stmt = $conn->prepare("SELECT * FROM Clientes WHERE ID = ?");
$stmt->bind_param('i', $cliente_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    // Si el cliente no existe, crear uno
    $username = $_SESSION['username'];
    $email = ""; // Puede que necesites ajustar esto para obtener el correo electrónico del usuario
    $telefono = ""; // Puede que necesites ajustar esto para obtener el teléfono del usuario

    $stmt = $conn->prepare("INSERT INTO Clientes (ID, Nombre, CorreoElectronico, Telefono) VALUES (?, ?, ?, ?)");
    $stmt->bind_param('isss', $cliente_id, $username, $email, $telefono);
    $stmt->execute();
    $stmt->close();
}

// Obtener detalles de la película
$sql = "SELECT * FROM Peliculas WHERE ID = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param('i', $pelicula_id);
$stmt->execute();
$result = $stmt->get_result();
$pelicula = $result->fetch_assoc();
$stmt->close();

// Obtener concesiones
$sql = "SELECT * FROM Concesiones";
$result = $conn->query($sql);
$concesiones = $result->fetch_all(MYSQLI_ASSOC);

// Manejo de compra de boletos y concesiones
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $funcion_id = $_POST['funcion_id'];
    $numero_asiento = $_POST['numero_asiento'];
    $precio_boleto = 10.00; // Ejemplo de precio fijo

    // Insertar boleto
    $stmt = $conn->prepare("INSERT INTO Boletos (Funcion_ID, Cliente_ID, Numero, Precio, TipoAsiento, FechaHora, NumeroAsiento) VALUES (?, ?, ?, ?, 'Normal', NOW(), ?)");
    $stmt->bind_param('iiidi', $funcion_id, $cliente_id, $numero_asiento, $precio_boleto, $numero_asiento);
    $stmt->execute();
    $boleto_id = $stmt->insert_id;
    $stmt->close();

    // Insertar concesiones compradas
    foreach ($_POST['concesiones'] as $concesion_id => $cantidad) {
        if ($cantidad > 0) {
            $stmt = $conn->prepare("INSERT INTO VentasConcesiones (Boleto_ID, Concesion_ID, Cantidad, PrecioTotal) VALUES (?, ?, ?, (SELECT Precio FROM Concesiones WHERE ID = ?) * ?)");
            $stmt->bind_param('iiiii', $boleto_id, $concesion_id, $cantidad, $concesion_id, $cantidad);
            $stmt->execute();
            $stmt->close();
        }
    }

    header('Location: index.php');
    exit();
}

// Obtener funciones disponibles para la película
$sql = "SELECT f.*, c.Nombre AS CineNombre, s.NumeroSala FROM Funciones f 
        INNER JOIN Cines c ON f.Cine_ID = c.ID 
        INNER JOIN Salas s ON f.Sala_ID = s.ID 
        WHERE Pelicula_ID = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param('i', $pelicula_id);
$stmt->execute();
$result = $stmt->get_result();
$funciones = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprar Boleto - <?php echo htmlspecialchars($pelicula['Titulo']); ?></title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h1>Comprar Boleto para <?php echo htmlspecialchars($pelicula['Titulo']); ?></h1>
        <form method="post" action="">
            <div class="form-group">
                <label for="funcion_id">Seleccionar Función</label>
                <select class="form-control" id="funcion_id" name="funcion_id" required>
                    <?php foreach ($funciones as $funcion): ?>
                        <option value="<?php echo $funcion['ID']; ?>">
                            Cine: <?php echo htmlspecialchars($funcion['CineNombre']); ?>, Sala: <?php echo htmlspecialchars($funcion['NumeroSala']); ?>, Fecha: <?php echo htmlspecialchars($funcion['FechaFuncion']); ?>, Hora: <?php echo htmlspecialchars($funcion['HoraInicio']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label for="numero_asiento">Número de Asiento</label>
                <input type="number" class="form-control" id="numero_asiento" name="numero_asiento" required>
            </div>
            <h3>Comprar Concesiones</h3>
            <?php foreach ($concesiones as $concesion): ?>
                <div class="form-group">
                    <label for="concesion_<?php echo $concesion['ID']; ?>"><?php echo htmlspecialchars($concesion['NombreProducto']); ?> - <?php echo htmlspecialchars($concesion['Precio']); ?>$</label>
                    <input type="number" class="form-control" id="concesion_<?php echo $concesion['ID']; ?>" name="concesiones[<?php echo $concesion['ID']; ?>]" value="0" min="0">
                </div>
            <?php endforeach; ?>
            <button type="submit" class="btn btn-primary">Comprar</button>
        </form>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
