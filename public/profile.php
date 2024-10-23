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

    // Step 4.2: Validate and update new password
    if (!empty($newPassword)) {
        if ($newPassword === $confirmNewPassword) {
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
            /** @noinspection ALL */
            $sql = "UPDATE users SET password = :password WHERE user_id = :user_id";
            if ($stmt = $pdo->prepare($sql)) {
                $stmt->bindParam(":password", $hashedPassword, PDO::PARAM_STR);
                $stmt->bindParam(":user_id", $_SESSION["user_id"], PDO::PARAM_INT);
                $stmt->execute();
                $updateMessages[] = 'Password updated successfully.';
            }
        } else {
            $updateMessages[] = 'New password and confirmation do not match.';
        }
    }


    // Step 4.3: Validate and update username
    if ($newUsername !== $currentUser['username']) {
        /** @noinspection ALL */
        $sql = "UPDATE users SET username = :username WHERE user_id = :user_id";
        if ($stmt = $pdo->prepare($sql)) {
            $stmt->bindParam(":username", $newUsername, PDO::PARAM_STR);
            $stmt->bindParam(":user_id", $_SESSION["user_id"], PDO::PARAM_INT);
            $stmt->execute();
            $updateMessages[] = 'Username updated successfully.';
        }
    }

    // Step 4.4: Update profile picture in the database
    if ($profilePicPath !== $currentUser['profile_pic']) {
        /** @noinspection ALL */
        $sql = "UPDATE users SET profile_pic = :profile_pic WHERE user_id = :user_id";
        if ($stmt = $pdo->prepare($sql)) {
            $stmt->bindParam(":profile_pic", $profilePicPath, PDO::PARAM_STR);
            $stmt->bindParam(":user_id", $_SESSION["user_id"], PDO::PARAM_INT);
            $stmt->execute();
            $updateMessages[] = 'Profile picture path updated in the database.';
        }
    }

    // Step 4.5: Handle no changes detected
    if (empty($updateMessages)) {
        $updateMessages[] = 'No changes detected.';
    }

    // Step 4.6: Store update messages in session and redirect
    $_SESSION["profile_update_messages"] = implode('<br>', $updateMessages);
    header("Location: profile.php");
    exit;

}

// PHP Codes finished here
?>


<!-- HTML Codes start here -->

<!-- Step 5: Write Head Section -->
<!DOCTYPE html>
<html lang="en">

<head>
    <!-- Step 5: Head section -->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile Management</title>
    <link rel="stylesheet" href="../assets/css/profile.css">
</head>

<body>
<div class="profile-management">
    <!-- Step 6: Display profile update messages -->
    <h3>Update Profile</h3>
    <?php if (!empty($_SESSION["profile_update_messages"])): ?>
        <div class="alert alert-info">
            <?= $_SESSION["profile_update_messages"]; ?>
        </div>
        <?php unset($_SESSION["profile_update_messages"]); ?>
    <?php endif; ?>


</body>
</html>