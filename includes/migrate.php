<?php

// Step 1: Include the Database connection file
require_once "db.php";

// Step 2: Include the CSS file for styling the Output
echo "<link rel='stylesheet' href='../assets/css/migrate.css'>";

// Step 3:Define a function to dynamically generate the 'Go Back' Link
function getGoBackLink() {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $uri = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');

    return $protocol . $host . str_replace('/includes', '/public', $uri) . '/dashboard.php';

}

// Step 4: List of SQL Migrations
$migrations = [
	'001_create_users_table' => "
		CREATE TABLE IF NOT EXISTS users (
			user_id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password VARCHAR(255) NOT NULL,
			date_created DATETIME DEFAULT CURRENT_TIMESTAMP
		); 
	",	
	'002_add_profile_pic_to_users' => "
		ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_pic VARCHAR(255) DEFAULT NULL;
	",	
	'003_create_machine_keys_table' => "
		CREATE TABLE IF NOT EXISTS machine_keys (
			key_id INT AUTO_INCREMENT PRIMARY KEY,
			machine_id VARCHAR(255) NOT NULL,
			encryption_key TEXT NOT NULL,
			received_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			stop_signal TINYINT(1) DEFAULT 0
		)
	",	
	'004_add_status_to_machine_keys' => "
		ALTER TABLE machine_keys ADD COLUMN IF NOT EXISTS status VARCHAR(255) DEFAULT 'pending';
	",	
];