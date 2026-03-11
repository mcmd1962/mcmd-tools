<?php
// config.php

// Bestand locaties:
$dbFile = 'rorik-dev-product-uitgifte.db';
$logFile = 'rorik-dev-product-uitgifte.log';
$indexFile = 'product-index.php';

// sectionName based on directory name
$sectionName = basename(__DIR__);

// Font grootte voor invoerveld
$inputFontSize = 'text-base'; // Tailwind class (default: text-base)

// Kleuren voor de cellen
$greenCellColor = 'bg-green-100'; // Tailwind class voor afgenomen producten
$redCellColor = 'bg-red-100';    // Tailwind class voor niet-opgehaalde producten
$sectionRedBgColor = 'bg-red-100'; // Tailwind class voor achtergrond van "Nog op te halen" sectie
$sectionGreenBgColor = 'bg-green-100'; // Tailwind class voor achtergrond van "Opgehaald" sectie

// Optie om namen te tonen
$toonNamen = true; // Zet op false om namen niet te tonen

// Standaard tijden voor uitgiftedagen
$defaultStartTijd = '09:00';  // Standaard starttijd
$defaultEindTijd = '14:00';   // Standaard eindtijd

?>

