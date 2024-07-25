<?php
require_once __DIR__ . '/../../config/db_connect.php';

function login($username, $password) {
    global $conn;
    
    $query = "SELECT * FROM Usuarios WHERE NombreUsuario = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['Contrasena'])) {
            session_start();
            $_SESSION['user_id'] = $user['ID'];
            $_SESSION['username'] = $user['NombreUsuario'];
            $_SESSION['role'] = $user['Rol'];
            return true;
        }
    }
    return false;
}

function register($username, $email, $password) {
    global $conn;
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $query = "INSERT INTO Usuarios (NombreUsuario, CorreoElectronico, Contrasena, Rol) VALUES (?, ?, ?, 'usuario')";
    $stmt = $conn->prepare($query);
    $stmt->bind_param('sss', $username, $email, $hashed_password);
    return $stmt->execute();
}

function isUsernameTaken($username) {
    global $conn;
    $query = "SELECT * FROM Usuarios WHERE NombreUsuario = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $stmt->store_result();
    return $stmt->num_rows > 0;
}

function isEmailTaken($email) {
    global $conn;
    $query = "SELECT * FROM Usuarios WHERE CorreoElectronico = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $stmt->store_result();
    return $stmt->num_rows > 0;
}

function logout() {
    session_start();
    session_unset();
    session_destroy();
}
?>