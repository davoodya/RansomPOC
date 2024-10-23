<?php
// Step 1: Start session and redirect if not logged in
session_start();

if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: login.php");
    exit;
}

// Step 2: Include database connection
require_once "../includes/db.php";