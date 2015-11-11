<?php

/*
 * Set up Memcache if available
 */
if(extension_loaded('memcached')){
	$GLOBALS['cache'] = new Memcached();
	$GLOBALS['cache']->addServer('127.0.0.1', 11211);
	$GLOBALS['cache_enabed'] = $GLOBALS['cache']->isPristine();
}
else{
	$GLOBALS['cache_enabed'] = false;
}

function cw_autoload($class_name) {
	if(is_file($class_name.'.php')){
		require_once $class_name.'.php';
	}
	else if (is_file(__DIR__.'/objects/'.$class_name.'.php')){
		require_once __DIR__.'/objects/'.$class_name.'.php';
	}
	else{
		return false;
	}
}


//CW autoload
spl_autoload_register('cw_autoload');