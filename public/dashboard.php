<?php

session_start();

// Step 1: Redirect to the login page if not logged in
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: login.php");
    exit;
}

// Step 2: Include the database connection file
require_once "../includes/db.php";