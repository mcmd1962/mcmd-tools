<?php
require_once __DIR__ . '/../../product-config.php';
require_once __DIR__ . '/../../product-functions.php';

// Start de sessie en laad configuratie als nog niet gedaan
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Haal statistieken, nog niet opgehaalde certificaten en producten op
$statistieken = getStatistieken($db);
$nietOpgehaaldeProductenPerProduct = getNietOpgehaaldeProductenPerProduct($db);
$totaalNietOpgehaaldeProducten = getTotaalNietOpgehaaldeProducten($db);
$producten = getProducten($db);
$productenCount = count($producten);
$productStatistieken = getProductStatistieken($db);

$productNamen = [];
foreach ($producten as $product) {
    $productNamen[] = $product['naam'];
};
if ($productenCount >=2) {
  $productNamen[] = 'Totaal';
}

?>

<!-- Overzichtsscherm -->
<div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
    <h1 class="text-2xl font-bold mb-4">Overzicht (Vandaag)</h1>

    <!-- Tabel met productstatistieken -->
    <div class="mt-6">
        <table class="min-w-full divide-y divide-gray-200 border border-gray-300">

            <thead class="bg-gray-100">
                <tr>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 bg-green-300 uppercase tracking-wider border">Product</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 bg-red-300 uppercase tracking-wider border">Nog op te halen</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 bg-green-300 uppercase tracking-wider border">Opgehaald</th>
                </tr>
            </thead>

            <tbody class="bg-white divide-y divide-gray-200">
                <!-- Product rijen -->
                <?php foreach ($productNamen as $productNaam): ?>
                    <?php
                        $stats = $productStatistieken[$productNaam] ?? [];
                        $tr_class_info = "";
                        $RedBgColor = "bg-red-100";
                        $GreenBgColor = "bg-green-100";
                        if ($productNaam == 'Totaal' ) {
                            $RedBgColor = "bg-red-300";
                            $GreenBgColor = "bg-green-300";
                            $tr_class_info = 'class="bg-gray-100 font-bold"';
                        }
                    ?>
                    <tr <?php echo $tr_class_info; ?> >
                        <td class="px-6 py-3 text-left text-sm text-gray-900 <?php echo $GreenBgColor; ?> border"><?php echo $productNaam; ?></td>
                        <td class="px-6 py-3 text-left text-sm text-gray-500 border <?php echo $RedBgColor; ?>">
                            <?php echo $stats['niet_opgehaald_certificaten'] ?? 0; ?> certificaten (
                            <?php echo $stats['percentage_niet_opgehaald_certificaten'] ?? 0; ?>%)
                            <br>
                            <?php echo $stats['niet_opgehaald_monden'] ?? 0; ?> monden (
                            <?php echo $stats['percentage_niet_opgehaald_monden'] ?? 0; ?>%)
                        </td>
                        <td class="px-6 py-3 text-left text-sm text-gray-500 border <?php echo $GreenBgColor; ?>">
                            <?php echo $stats['opgehaald_certificaten'] ?? 0; ?> certificaten (
                            <?php echo $stats['percentage_opgehaald_certificaten'] ?? 0; ?>%)<br>
                            <?php echo $stats['opgehaald_monden'] ?? 0; ?> monden ( 
                            <?php echo $stats['percentage_opgehaald_monden'] ?? 0; ?>%)
                        </td>
                    </tr>
                <?php endforeach; ?>

            </tbody>
        </table>
    </div>
</div>

