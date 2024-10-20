<?php

// Step 1: Include the Database connection file
require_once "db.php";

// Step 2: Include the CSS file for styling the Output
echo "<link rel='stylesheet' href='../assets/css/migrate.css'>";

// Step 3:Define a function to dynamically generate the 'Go Back' Link
function getGoBackLink() {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $uri = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');

    return $protocol . $host . str_replace('/includes', '/public', $uri) . '/dashboard.php';

}

