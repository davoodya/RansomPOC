<?php

// Step 1: Start session and check if already logged in
global $pdo;
session_start();

if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    header('location: dashboard.php');
    exit;
}

// Step 2: Include database connection
require_once "../includes/db.php";

$username = $password = "";
$err = "";

// Step 3: Process login form submission
// Give username and password from user and then POST it to a database
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim(filter_input(INPUT_POST, "username", FILTER_SANITIZE_STRING));
    $sql = "SELECT user_id, username, password FROM users WHERE username = :username";

    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindParam(":username", $username, PDO::PARAM_STR);

        if ($stmt->execute()) {
            if ($stmt->rowCount() == 1) {
                if ($row = $stmt->fetch()) {
                    $hashed_password = $row["password"];

                    if (password_verify(filter_input(INPUT_POST, "password", FILTER_SANITIZE_STRING), $hashed_password)) {
                        $_SESSION["loggedin"] = true;
                        $_SESSION["user_id"] = $row["user_id"];
                        $_SESSION["username"] = $row["username"];
                        header("location: dashboard.php");
                        exit;
                    } else {
                        $err = "Invalid password.";
                    }
                }
            } else {
                $err = "Invalid username.";
            }
        } else {
            $err = "Something went wrong. Please try again later.";
        }
        unset($stmt);
    }
    unset($pdo);
}

