<?php

// Start de sessie en laad configuratie als nog niet gedaan
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Inclusief configuratiebestand
require_once 'product-config.php';
require_once 'product-functions.php';
require_once 'templates/minify.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Controleer of de uitgifte open is
$uitgifteOpen = isUitgifteOpen($db);


$paginaTitel = "Product Uitgifte";
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <?php include __DIR__ . '/templates/head.php'; ?>

    <style>
        /* Configureerbare kleuren uit config.php */
        .green-cell {
            background-color: <?php echo $greenCellColor; ?>;
        }
        .red-cell {
            background-color: <?php echo $redCellColor; ?>;
        }
        .section-red {
            background-color: <?php echo $sectionRedBgColor; ?>;
        }
        .section-green {
            background-color: <?php echo $sectionGreenBgColor; ?>;
        }
        #certificatenDropdown {
            min-width: 300px;
        }
    </style>
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">

    <div class="container w-full mx-auto pt-10 pb-10">
        <div class="w-full px-4 text-xl text-gray-800 leading-normal">
            <div class="bg-white shadow-md rounded px-8 pt-6 pb-4 mb-2">
                <?php include __DIR__ . '/templates/header.php'; ?>
            </div>

            <?php if (!$uitgifteOpen): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                    <strong class="font-bold">Uitgifte gesloten</strong>
                </div>
            <?php else: ?>
                <!-- Registratie Formulier -->
                <?php include __DIR__ . '/snippets/uitgifte/registratie.php'; ?>

                <!-- Laatste Registratie -->
                <?php include __DIR__ . '/snippets/uitgifte/laatste-registratie.php'; ?>

                <!-- Overzichtsscherm -->
                <?php include __DIR__ . '/snippets/uitgifte/overzicht.php'; ?>

                <!-- Nog Niet Opgehaalde Certificaten Overzicht -->
                <?php include __DIR__ . '/snippets/uitgifte/nog-niet-opgekomen-leden.php'; ?>

            <?php endif; ?>
            <?php include __DIR__ . '/templates/footer.php'; ?>
        </div>
    </div>
</body>
</html>
