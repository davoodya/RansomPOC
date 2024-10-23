<?php

// Step 1: Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Step 2: Set the header for JSON content type and Include database connection
header('Content-Type: application/json');
require_once '../db.php';
