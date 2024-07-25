<?php
$servername = "localhost";
$username = "root";
$password = "Gian3056";
$dbname = "cine_GMAC";

// Crear conexión
$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar conexión
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}
?>
