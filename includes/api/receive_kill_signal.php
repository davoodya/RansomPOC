<?php

// Step 1: Include the database connection file
global $pdo;
require_once '../db.php';

// Step 2: Initialize a response array
$response = ['success' => false];

// Step 3: Check if machine_id is set in the POST request
if (isset($_POST['machine_id'])) {
    $machine_id = $_POST['machine_id'];

    // Step 3.1: Try to execute the SQL update statement
    try {
        // Step 3.2: Prepare the SQL statement to update stop_signal
        $stmt = $pdo->prepare("UPDATE machine_keys SET stop_signal = 1 WHERE machine_id = :machine_id");


        // Step 3.3: Bind the machine_id parameter
        $stmt->bindParam(':machine_id', $machine_id);

    }}