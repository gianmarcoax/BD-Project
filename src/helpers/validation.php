<?php
function validatePelicula($genero = null, $duracion = null, $clasificacion = null) {
    $validGeneros = ['Accion', 'Comedia', 'Drama', 'Terror', 'Ciencia Ficcion'];
    $validClasificaciones = ['G', 'PG', 'PG-13', 'R', 'NC-17'];

    if ($genero === null && $duracion === null && $clasificacion === null) {
        return [
            'generos' => $validGeneros,
            'clasificaciones' => $validClasificaciones,
        ];
    }

    if (!in_array($genero, $validGeneros)) {
        return 'Genero no válido.';
    }
    if ($duracion <= 0) {
        return 'Duracion debe ser mayor que 0.';
    }
    if (!in_array($clasificacion, $validClasificaciones)) {
        return 'Clasificacion no válida.';
    }
    return true;
}
    
function validateSala($numeroSala, $capacidad, $tipoSala) {
    $validTiposSala = ['2D', '3D', 'IMAX', 'VIP'];

    if ($numeroSala <= 0) {
        return 'NumeroSala debe ser mayor que 0.';
    }
    if ($capacidad <= 0) {
        return 'Capacidad debe ser mayor que 0.';
    }
    if (!in_array($tipoSala, $validTiposSala)) {
        return 'TipoSala no válida.';
    }
    return true;
}

function validateFuncion($cine_id, $sala_id, $fechaFuncion, $horaInicio) {
    if (empty($cine_id)) {
        return 'Debe seleccionar un cine.';
    }
    if (empty($sala_id)) {
        return 'Debe seleccionar una sala.';
    }
    if (strtotime($fechaFuncion) < strtotime(date('Y-m-d'))) {
        return 'Fecha de función debe ser mayor o igual a la fecha actual.';
    }
    if (empty($horaInicio)) {
        return 'Hora de inicio es obligatoria.';
    }
    return true;
}

function validateBoleto($precio, $tipoAsiento, $numeroAsiento) {
    $validTiposAsiento = ['Normal', 'VIP'];

    if ($precio <= 0) {
        return 'Precio debe ser mayor que 0.';
    }
    if (!in_array($tipoAsiento, $validTiposAsiento)) {
        return 'TipoAsiento no válido.';
    }
    if ($numeroAsiento <= 0) {
        return 'NumeroAsiento debe ser mayor que 0.';
    }
    return true;
}

function validateTransaccion($monto, $metodoPago) {
    $validMetodosPago = ['Efectivo', 'Tarjeta de Crédito', 'Tarjeta de Débito'];

    if ($monto <= 0) {
        return 'Monto debe ser mayor que 0.';
    }
    if (!in_array($metodoPago, $validMetodosPago)) {
        return 'MetodoPago no válido.';
    }
    return true;
}

function validateConcesion($precio) {
    if ($precio <= 0) {
        return 'Precio debe ser mayor que 0.';
    }
    return true;
}

function validateUsername($username) {
    if (empty($username)) {
        return "El nombre de usuario no puede estar vacío.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
        return "El nombre de usuario debe tener entre 3 y 20 caracteres y solo puede contener letras, números y guiones bajos.";
    }
    return true;
}

function validatePassword($password) {
    if (strlen($password) < 8) {
        return false;
    }
    if (!preg_match("/[A-Z]/", $password)) {
        return false;
    }
    if (!preg_match("/[a-z]/", $password)) {
        return false;
    }
    if (!preg_match("/[0-9]/", $password)) {
        return false;
    }
    return true;
}
?>
