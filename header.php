<?php
require_once __DIR__.'/settings/site_info.php';
require_once 'connect.php';
if (isset($SHALL_LOG_OUT)) {
	$_SESSION = array();
	setcookie(session_name(), '', time() - 42000);
	session_destroy();
	header('location: index.php');
}
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title><?php echo $site_name; ?></title>
		<link rel="stylesheet" type="text/css" href="css/style.css" />
		<link rel="stylesheet" type="text/css" href="css/font-awesome.css" />
	</head>
	<body>
		<div id="container" class="clearfix">