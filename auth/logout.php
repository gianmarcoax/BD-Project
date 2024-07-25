<?php
session_start();
require_once '../src/middlewares/auth.php';

// Destruir la sesión
session_unset();
session_destroy();

// Redirigir al usuario a la página principal
header('Location: ../index.php');
exit();
?>