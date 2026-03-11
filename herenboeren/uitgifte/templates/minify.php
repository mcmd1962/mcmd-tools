<?php

require_once __DIR__ . '/../product-config.php';
require_once __DIR__ . '/../product-functions.php';

// Start de sessie en laad configuratie als nog niet gedaan
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// make sure to update the path to where you cloned the projects to!
$libPath = 'lib';
require_once $libPath . '/minify/src/Minify.php';
require_once $libPath . '/minify/src/CSS.php';
require_once $libPath . '/minify/src/JS.php';
require_once $libPath . '/minify/src/Exception.php';
require_once $libPath . '/minify/src/Exceptions/BasicException.php';
require_once $libPath . '/minify/src/Exceptions/FileImportException.php';
require_once $libPath . '/minify/src/Exceptions/IOException.php';
require_once $libPath . '/path-converter/src/ConverterInterface.php';
require_once $libPath . '/path-converter/src/Converter.php';

use MatthiasMullie\Minify;
ob_start(function($buffer) {
    $minifier = new Minify\CSS($buffer);
    return $minifier->minify();
});


?>


