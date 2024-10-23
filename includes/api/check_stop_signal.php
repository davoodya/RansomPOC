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

    // Step 4.1: Execute the prepared statement and fetch the result
    if ($stmt->execute()) {
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        echo json_encode(['stop_signal' => $result['stop_signal'] ?? 0]);
    } else {
        passthru('echo "Error fetching stop signal."');
    }
}
