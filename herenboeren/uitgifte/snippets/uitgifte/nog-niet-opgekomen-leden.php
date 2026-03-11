<?php
require_once __DIR__ . '/../../product-config.php';
require_once __DIR__ . '/../../product-functions.php';

// Start de sessie en laad configuratie als nog niet gedaan
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

$nogNietOpgehaaldeCertificaten = getNogNietOpgehaaldeCertificaten($db);

?>

<!-- Nog Niet Opgehaalde Certificaten Overzicht -->
<div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
    <h1 class="text-2xl font-bold mb-4">Certificaten die vandaag nog niet hebben opgehaald</h1>
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
            <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Certificaat</th>
                <?php if ($toonNamen): ?>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Naam</th>
                <?php endif; ?>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Product</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Monden</th>
            </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
            <?php foreach ($nogNietOpgehaaldeCertificaten as $certificaat): ?>
                <tr class="<?php echo ($certificaat['certificaat'] % 10 == 0) ? 'bg-gray-100' : ''; ?>">
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 border"><?php echo $certificaat['certificaat']; ?></td>
                    <?php if ($toonNamen): ?>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $certificaat['lid_naam'] ?? '-'; ?></td>
                    <?php endif; ?>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $certificaat['product']; ?></td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $certificaat['monden']; ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
