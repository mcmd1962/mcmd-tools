<?php
// Inclusief configuratiebestand
require_once 'product-registratie-config.php';

// Controleer of er een export wordt aangevraagd
if (isset($_GET['export']) && $_GET['export'] == 'csv') {
    exportToCSV();
    exit;
}

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Functie om alle leden op te halen
function getLeden($db) {
    $result = $db->query("SELECT nummer, product_id, hoeveelheid FROM leden ORDER BY nummer");
    $leden = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $leden[$row['nummer']] = $row;
    }
    return $leden;
}

// Functie om alle uitgiftedata op te halen
function getUitgiftedata($db) {
    $result = $db->query("SELECT id, uitgiftedatum FROM uitgiftedatum ORDER BY uitgiftedatum");
    $data = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $data[] = $row;
    }
    return $data;
}

// Functie om alle registraties op te halen
function getRegistraties($db) {
    $result = $db->query("SELECT nummer, uitgiftedag FROM registraties");
    $registraties = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $registraties[$row['nummer']][] = $row['uitgiftedag'];
    }
    return $registraties;
}

// Functie om alle producten op te halen
function getProducten($db) {
    $result = $db->query("SELECT id, naam FROM producten");
    $producten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $producten[$row['id']] = $row['naam'];
    }
    return $producten;
}

// Functie om het aantal opgehaalde en niet-opgehaalde leden per uitgiftedatum te berekenen
function getOpgehaaldPerDatum($db, $uitgiftedata) {
    $opgehaaldPerDatum = [];
    foreach ($uitgiftedata as $data) {
        $uitgiftedagId = $data['id'];
        $result = $db->query("SELECT COUNT(DISTINCT nummer) as opgehaald FROM registraties WHERE uitgiftedag = $uitgiftedagId");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $opgehaaldPerDatum[$data['uitgiftedatum']] = [
            'opgehaald' => $row['opgehaald'],
            'niet_opgehaald' => 0,
        ];
    }

    foreach ($uitgiftedata as $data) {
        $uitgiftedagId = $data['id'];
        $result = $db->query("
            SELECT COUNT(DISTINCT leden.nummer) as niet_opgehaald
            FROM leden
            WHERE leden.nummer NOT IN (
                SELECT nummer FROM registraties WHERE uitgiftedag = $uitgiftedagId
            )
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $opgehaaldPerDatum[$data['uitgiftedatum']]['niet_opgehaald'] = $row['niet_opgehaald'];
    }

    return $opgehaaldPerDatum;
}

// Functie om het aantal opgehaalde en niet-opgehaalde leden per product te berekenen
function getOpgehaaldPerProduct($db, $producten) {
    $opgehaaldPerProduct = [];
    foreach ($producten as $productId => $productNaam) {
        $result = $db->query("
            SELECT COUNT(DISTINCT leden.nummer) as opgehaald
            FROM leden
            JOIN registraties ON leden.nummer = registraties.nummer
            WHERE leden.product_id = $productId
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $opgehaaldPerProduct[$productNaam]['opgehaald'] = $row['opgehaald'];

        $result = $db->query("
            SELECT COUNT(DISTINCT leden.nummer) as niet_opgehaald
            FROM leden
            WHERE leden.product_id = $productId AND leden.nummer NOT IN (
                SELECT nummer FROM registraties
            )
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $opgehaaldPerProduct[$productNaam]['niet_opgehaald'] = $row['niet_opgehaald'];
    }

    return $opgehaaldPerProduct;
}

// Functie om het CSV-rapport te genereren
function exportToCSV() {
    global $dbFile;

    $db = new SQLite3($dbFile);
    $leden = getLeden($db);
    $uitgiftedata = getUitgiftedata($db);
    $registraties = getRegistraties($db);
    $producten = getProducten($db);

    // Set headers for CSV download
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="product_rapport.csv"');

    // Open output stream
    $output = fopen('php://output', 'w');

    // Write BOM for UTF-8 support
    fwrite($output, "\xEF\xBB\xBF");

    // Write headers
    $headers = ['Lidnummer', 'Product'];
    foreach ($uitgiftedata as $data) {
        $headers[] = date('d-m-Y', strtotime($data['uitgiftedatum']));
    }
    fputcsv($output, $headers, ';', '"');

    // Write data
    foreach ($leden as $lidnummer => $lid) {
        $row = [$lidnummer, $producten[$lid['product_id']]];
        foreach ($uitgiftedata as $data) {
            $uitgiftedagId = $data['id'];
            $hasRegistration = isset($registraties[$lidnummer]) && in_array($uitgiftedagId, $registraties[$lidnummer]);
            $row[] = $hasRegistration ? 'X' : '';
        }
        fputcsv($output, $row, ';', '"');
    }

    fclose($output);
    exit;
}

// Haal de gegevens op
$leden = getLeden($db);
$uitgiftedata = getUitgiftedata($db);
$registraties = getRegistraties($db);
$producten = getProducten($db);
$opgehaaldPerDatum = getOpgehaaldPerDatum($db, $uitgiftedata);
$opgehaaldPerProduct = getOpgehaaldPerProduct($db, $producten);
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Rapport</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .green-cell {
            background-color: #d1fae5;
        }
        .red-cell {
            background-color: #fee2e2;
        }
    </style>
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
    <div class="container w-full mx-auto pt-20 px-4">
        <div class="w-full px-4 text-xl text-gray-800 leading-normal">
            <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
                <h1 class="text-2xl font-bold mb-4">Rapport: Uitgifte per Lid</h1>
                <div class="mb-4 flex space-x-4">
                    <a href="?export=csv" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">Export naar CSV</a>
                </div>

                <!-- Totalen per Datum -->
                <div class="mb-8">
                    <h2 class="text-xl font-bold mb-4">Totalen per Datum</h2>
                    <table class="min-w-full divide-y divide-gray-200 border border-gray-300">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Datum</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Opgehaald</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Niet Opgehaald</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($opgehaaldPerDatum as $datum => $data): ?>
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 border"><?php echo date('d-m-Y', strtotime($datum)); ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $data['opgehaald']; ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $data['niet_opgehaald']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Totalen per Product -->
                <div class="mb-8">
                    <h2 class="text-xl font-bold mb-4">Totalen per Product</h2>
                    <table class="min-w-full divide-y divide-gray-200 border border-gray-300">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Product</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Opgehaald</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Niet Opgehaald</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($opgehaaldPerProduct as $productNaam => $data): ?>
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 border"><?php echo $productNaam; ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $data['opgehaald']; ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $data['niet_opgehaald']; ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Rapport -->
                <div class="overflow-x-auto">
                    <h2 class="text-xl font-bold mb-4">Uitgifte per Lid</h2>
                    <table class="min-w-full divide-y divide-gray-200 border border-gray-300">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Lidnummer</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Product</th>
                                <?php foreach ($uitgiftedata as $data): ?>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border"><?php echo date('d-m-Y', strtotime($data['uitgiftedatum'])); ?></th>
                                <?php endforeach; ?>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($leden as $lidnummer => $lid): ?>
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 border"><?php echo $lidnummer; ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border"><?php echo $producten[$lid['product_id']]; ?></td>
                                    <?php foreach ($uitgiftedata as $data): ?>
                                        <?php
                                        $uitgiftedagId = $data['id'];
                                        $hasRegistration = isset($registraties[$lidnummer]) && in_array($uitgiftedagId, $registraties[$lidnummer]);
                                        ?>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 border <?php echo $hasRegistration ? 'green-cell' : 'red-cell'; ?>">
                                            <?php echo $hasRegistration ? 'X' : ''; ?>
                                        </td>
                                    <?php endforeach; ?>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
