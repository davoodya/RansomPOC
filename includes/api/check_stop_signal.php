<?php

// Step 1: Enable error reporting for debugging
global $pdo;
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Step 2: Set the header for JSON content type and Include database connection
header('Content-Type: application/json');
require_once '../db.php';

// Step 4: Check if machine_id is provided and fetch stop_signal from the database
if (isset($_GET['machine_id'])) {
    $machine_id = $_GET['machine_id'];
    $stmt = $pdo->prepare("SELECT stop_signal FROM machine_keys WHERE machine_id = :machine_id");
    $stmt->bindParam(':machine_id', $machine_id);
}
