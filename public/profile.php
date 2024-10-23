<?php
// Step 1: Start session and redirect if not logged in
global $pdo;
session_start();

if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: login.php");
    exit;
}

// Step 2: Include database connection
require_once "../includes/db.php";

// Step 3: Fetch current user information
$currentUser = [];
/** @noinspection ALL */
$sql = "SELECT username, profile_pic FROM users WHERE user_id = :user_id";
if ($stmt = $pdo->prepare($sql)) {
    $stmt->bindParam(":user_id", $_SESSION["user_id"], PDO::PARAM_INT);
    $stmt->execute();
    $currentUser = $stmt->fetch(PDO::FETCH_ASSOC);
}


$updateMessages = [];


// Step 4: Process form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $newUsername = trim($_POST["username"] ?? '');
    $newPassword = trim($_POST["new_password"] ?? '');
    $confirmNewPassword = trim($_POST["confirm_new_password"] ?? '');
    $profilePicPath = $currentUser['profile_pic'];

    // Step 4.1: Update profile picture if provided
    if (isset($_FILES["profile_pic"]) && $_FILES["profile_pic"]["error"] == UPLOAD_ERR_OK) {
        $targetDir = "../uploads/";
        $fileExtension = pathinfo($_FILES["profile_pic"]["name"], PATHINFO_EXTENSION);
        $targetFile = $targetDir . uniqid() . '.' . $fileExtension;
        if (move_uploaded_file($_FILES["profile_pic"]["tmp_name"], $targetFile)) {
            $profilePicPath = $targetFile;
            $updateMessages[] = 'Profile picture updated successfully.';
        } else {
            $updateMessages[] = 'Error uploading profile picture.';
        }
    }


}

