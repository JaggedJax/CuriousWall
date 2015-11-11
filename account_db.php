﻿<?php
require_once 'connect.php';

$_POST['user'] = trim($_POST['user']);
$_POST['pass'] = trim($_POST['pass']);

$pass_salt = 'just_for_demo';

if ($_POST['method'] == 'login') {
	if (!$_POST['user'] || !$_POST['pass'])
		die('Fill in username and password.');

	$query = $db->prepare('SELECT user_id, user_pass, user_name, permissions FROM users WHERE user_name = ?');
	$query->execute(array($_POST['user']));
	$row = $query->fetch(PDO::FETCH_ASSOC);
	
	//TODO: Limit login attempts
	if(!Crypt::verify($_POST['pass'], $row['user_pass'])){
		die('Incorrect password.');
	}

	if (!$row['user_name']) {
		die('Incorrect username.');
	}

	$_SESSION['user_name'] = $row['user_name'];
	$_SESSION['user_id'] = $row['user_id'];
	$_SESSION['permissions'] = $row['permissions'];
	die('Success.');
} else if ($_POST['method'] == 'register') {
	if (!$_POST['user'] || !$_POST['pass'])
		die('Fill in username and password.');
	if (!preg_match("/^[a-zA-Z0-9_\.\!\@\#\$\%\^\&\*]+$/u", $_POST['user'])) {
		die('Username can only contain a-z A-Z 0-9 and underscore.');
	}
	if (strlen($_POST['user']) >= 16) {
		die('Username must be less than 16 characters.');
	}

	$query = $db->prepare("SELECT user_id FROM users WHERE user_name LIKE ?");
	$query->execute(array($_POST['user']));
	if ($query->rowCount() > 0) {
		die('Username already occupied.');
	}

	$query = $db->prepare("INSERT INTO users(user_name,user_pass) VALUES(?,?)");
	$query->execute(array($_POST['user'], Crypt::hash_blowfish($_POST['pass'])));
	if ($query->rowCount() < 1) {
		die('Username already occupied.');
	}

	$_SESSION['user_name'] = $_POST['user'];
	$_SESSION['user_id'] = $db->lastInsertId();
	$_SESSION['permissions'] = 0;

	die('Success. <a href = "index.php">[Click here for frontpage]</a>');
} else {
	header('location: index.php');
}