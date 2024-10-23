<?php

// Step 1: Include the database connection file
require_once '../db.php';

// Step 2: Initialize a response array
$response = ['success' => false];

// Step 3: Check if machine_id is set in the POST request
if (isset($_POST['machine_id'])) {
    $machine_id = $_POST['machine_id'];
}