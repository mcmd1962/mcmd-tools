<?php
require_once __DIR__ . '/../product-config.php';
require_once __DIR__ . '/../product-functions.php';
?>

<footer class="mt-16 text-center text-gray-500 text-sm">
    <p>Product Uitgiftesysteem &copy; <?php echo date('Y'); ?> | Gebruiker: <?php echo htmlspecialchars(getGebruikersnaam()); ?></p>
</footer>

