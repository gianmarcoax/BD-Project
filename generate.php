<?php
$passwords = [
    'adminpassword',
    'user1password',
    'user2password'
];

foreach ($passwords as $password) {
    echo password_hash($password, PASSWORD_DEFAULT) . "\n";
}
?>