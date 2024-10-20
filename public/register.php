<?php

// Step 1: Start Session and Include Database Connections

session_start();

require_once "../includes/db.php";

// Step 2: Check if the user is already logged in
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    header("location: dashboard.php");
    exit;
}

$username = $password = $confrim_password = "";
$username_err = $password_err = $confrim_password_err = "";

// Step 3: Process login form submission