<?php
require_once __DIR__ . '/../product-config.php';
require_once __DIR__ . '/../product-functions.php';

// Start de sessie en laad configuratie als nog niet gedaan
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
?>

<div class="flex justify-between items-center mb-6">
    <!-- links (links uitgelijnd) -->
    <div class="w-full md:w-auto mb-4 md:mb-0">
        <a href="<?php echo $indexFile; ?>" class="inline-block bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded mb-4 md:mb-0 focus:outline-none focus:shadow-outline">
            <i class="fas fa-arrow-left mr-2"></i>Terug naar Overzicht
        </a>
    </div>

    <!-- midden (centraal uitgelijnd) -->
    <div class="w-full md:w-auto mb-4 md:mb-0 text-center">
        <h1 class="text-2xl font-bold text-gray-800"><?php echo $sectionName; ?></h1>
    </div>

    <!-- rechts (rechts uitgelijnd) -->
    <div class="w-full md:w-auto text-center md:text-right">
        <h1 class="text-2xl font-bold mb-2"><?php echo $paginaTitel; ?></h1>
        <p class="text-gray-700"><i class="fas fa-user mr-2"></i>Ingelogd als: <span class="font-semibold"><?php echo htmlspecialchars(getGebruikersnaam()); ?></span></p>
        <p class="text-sm text-gray-500"><?php echo date('d-m-Y H:i'); ?></p>
    </div>
</div>

