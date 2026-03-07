<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Functie om alle uitgiftedata met transacties op te halen (gesorteerd van oud naar nieuw)
function getUitgiftedataMetTransacties($db) {
    $result = $db->query("
        SELECT DISTINCT u.id, u.uitgiftedatum
        FROM uitgiftedatum u
        JOIN registraties r ON u.id = r.uitgiftedag
        ORDER BY u.uitgiftedatum ASC
    ");
    $data = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $data[] = $row;
    }
    return $data;
}

// Functie om alle certificaten op te halen
function getAlleCertificaten($db) {
    $result = $db->query("SELECT certificaat FROM leden GROUP BY certificaat ORDER BY certificaat");
    $certificaten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $certificaten[] = $row['certificaat'];
    }
    return $certificaten;
}

// Functie om productinformatie per certificaat op te halen
function getProductInfoPerCertificaat($db) {
    $result = $db->query("
        SELECT certificaat,
               GROUP_CONCAT(naam || ' (' || monden || ')', ', ') as producten
        FROM leden l
        JOIN producten p ON l.product_id = p.id
        GROUP BY certificaat
    ");
    $productInfo = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $productInfo[$row['certificaat']] = $row['producten'];
    }
    return $productInfo;
}

// Functie om op te halen welke certificaten zijn opgehaald op geselecteerde datums
function getOpgehaaldeCertificatenPerDatum($db, $uitgiftedatumIds) {
    if (empty($uitgiftedatumIds)) {
        return [];
    }

    $placeholders = implode(',', array_fill(0, count($uitgiftedatumIds), '?'));
    $query = "SELECT certificaat, uitgiftedag FROM registraties WHERE uitgiftedag IN ($placeholders)";

    $stmt = $db->prepare($query);
    foreach ($uitgiftedatumIds as $i => $id) {
        $stmt->bindValue($i+1, $id, SQLITE3_INTEGER);
    }

    $result = $stmt->execute();
    $opgehaaldeData = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $opgehaaldeData[$row['uitgiftedag']][] = $row['certificaat'];
    }

    // Zorg dat elke datum een entry heeft
    foreach ($uitgiftedatumIds as $datumId) {
        if (!isset($opgehaaldeData[$datumId])) {
            $opgehaaldeData[$datumId] = [];
        }
    }

    return $opgehaaldeData;
}

// Functie om het totaal aantal opgehaalde keren per certificaat te berekenen
function getTotaalOpgehaaldPerCertificaat($db, $certificaten, $uitgiftedatumIds) {
    if (empty($uitgiftedatumIds) || empty($certificaten)) {
        return [];
    }

    $totaalPerCertificaat = [];

    // Maak een lijst van placeholders voor de datums
    $datumPlaceholders = implode(',', array_fill(0, count($uitgiftedatumIds), '?'));

    foreach ($certificaten as $certificaat) {
        $query = "SELECT COUNT(*) as totaal FROM registraties
                  WHERE certificaat = ? AND uitgiftedag IN ($datumPlaceholders)";

        $stmt = $db->prepare($query);
        $stmt->bindValue(1, $certificaat, SQLITE3_INTEGER);

        // Bind alle datum IDs
        foreach ($uitgiftedatumIds as $i => $id) {
            $stmt->bindValue($i+2, $id, SQLITE3_INTEGER);
        }

        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $totaalPerCertificaat[$certificaat] = $row['totaal'];
    }

    return $totaalPerCertificaat;
}

// Functie om het totaal aantal opgehaalde certificaten per datum te berekenen
function getTotaalOpgehaaldPerDatum($db, $uitgiftedatumIds) {
    if (empty($uitgiftedatumIds)) {
        return [];
    }

    $totaalPerDatum = [];
    foreach ($uitgiftedatumIds as $datumId) {
        $result = $db->query("SELECT COUNT(*) as totaal FROM registraties WHERE uitgiftedag = $datumId");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $totaalPerDatum[$datumId] = $row['totaal'];
    }

    return $totaalPerDatum;
}

// Functie om rapportgegevens op te halen voor een specifieke datum
function getRapportGegevens($db, $uitgiftedatumId) {
    // Haal basisinformatie over de uitgiftedatum
    $result = $db->query("SELECT uitgiftedatum, starttijd, eindtijd FROM uitgiftedatum WHERE id = $uitgiftedatumId");
    $uitgiftedatumInfo = $result->fetchArray(SQLITE3_ASSOC);

    // Haal alle registraties voor deze datum
    $result = $db->query("
        SELECT r.certificaat, r.gebruiker, r.registratie_tijd, l.product_id, p.naam as product, l.monden
        FROM registraties r
        JOIN leden l ON r.certificaat = l.certificaat
        JOIN producten p ON l.product_id = p.id
        WHERE r.uitgiftedag = $uitgiftedatumId
        ORDER BY r.registratie_tijd
    ");
    $registraties = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $registraties[] = $row;
    }

    // Haal statistieken voor deze datum
    $result = $db->query("SELECT COUNT(*) as totalCertificaten FROM registraties WHERE uitgiftedag = $uitgiftedatumId");
    $stats = $result->fetchArray(SQLITE3_ASSOC);
    $totalCertificaten = $stats['totalCertificaten'];

    $result = $db->query("
        SELECT SUM(l.monden) as totalMonden
        FROM registraties r
        JOIN leden l ON r.certificaat = l.certificaat
        WHERE r.uitgiftedag = $uitgiftedatumId
    ");
    $stats = $result->fetchArray(SQLITE3_ASSOC);
    $totalMonden = $stats['totalMonden'] ?? 0;

    // Haal certificaten die niet zijn opgehaald voor deze datum
    $result = $db->query("
        SELECT l.certificaat, p.naam as product, l.monden
        FROM leden l
        JOIN producten p ON l.product_id = p.id
        WHERE l.certificaat NOT IN (
            SELECT certificaat FROM registraties WHERE uitgiftedag = $uitgiftedatumId
        )
        ORDER BY l.certificaat
    ");
    $nietOpgehaaldeCertificaten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $nietOpgehaaldeCertificaten[] = $row;
    }

    return [
        'uitgiftedatumInfo' => $uitgiftedatumInfo,
        'registraties' => $registraties,
        'totalCertificaten' => $totalCertificaten,
        'totalMonden' => $totalMonden,
        'nietOpgehaaldeCertificaten' => $nietOpgehaaldeCertificaten
    ];
}

// Functie om kleur te bepalen op basis van percentage
function getKleurOpBasisVanPercentage($waarde, $max) {
    if ($max == 0) return 'bg-gray-200';

    $percentage = ($waarde / $max) * 100;

    if ($percentage == 0) {
        return 'bg-gray-200';
    } elseif ($percentage < 33) {
        return 'bg-red-200';
    } elseif ($percentage < 66) {
        return 'bg-yellow-200';
    } else {
        return 'bg-green-200';
    }
}

// Haal alleen uitgiftedata met transacties op (gesorteerd van oud naar nieuw)
$uitgiftedata = getUitgiftedataMetTransacties($db);
$alleCertificaten = getAlleCertificaten($db);

// Standaard selecteer de laatste 7 datums met transacties (van oud naar nieuw)
$geselecteerdeUitgiftedatumIds = !empty($uitgiftedata) ? array_slice(array_column($uitgiftedata, 'id'), -7) : [];
$opgehaaldeData = [];
$productInfoPerCertificaat = [];
$totaalPerCertificaat = [];
$totaalPerDatum = [];
$rapportGegevens = [];

if (!empty($geselecteerdeUitgiftedatumIds)) {
    $opgehaaldeData = getOpgehaaldeCertificatenPerDatum($db, $geselecteerdeUitgiftedatumIds);
    $productInfoPerCertificaat = getProductInfoPerCertificaat($db);
    $totaalPerCertificaat = getTotaalOpgehaaldPerCertificaat($db, $alleCertificaten, $geselecteerdeUitgiftedatumIds);
    $totaalPerDatum = getTotaalOpgehaaldPerDatum($db, $geselecteerdeUitgiftedatumIds);

    // Bepaal het maximum aantal opgehaalde keren voor kleurcodering
    $maxTotaal = !empty($totaalPerCertificaat) ? max($totaalPerCertificaat) : 0;

    // Haal rapportgegevens op voor elke geselecteerde datum
    foreach ($geselecteerdeUitgiftedatumIds as $datumId) {
        $rapportGegevens[$datumId] = getRapportGegevens($db, $datumId);
    }
}

// Verwerk het formulier voor het selecteren van datums
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['selecteer_datums'])) {
        $geselecteerdeUitgiftedatumIds = $_POST['uitgiftedatum_ids'] ?? [];
        if (!empty($geselecteerdeUitgiftedatumIds)) {
            $opgehaaldeData = getOpgehaaldeCertificatenPerDatum($db, $geselecteerdeUitgiftedatumIds);
            $productInfoPerCertificaat = getProductInfoPerCertificaat($db);
            $totaalPerCertificaat = getTotaalOpgehaaldPerCertificaat($db, $alleCertificaten, $geselecteerdeUitgiftedatumIds);
            $totaalPerDatum = getTotaalOpgehaaldPerDatum($db, $geselecteerdeUitgiftedatumIds);

            // Bepaal het maximum aantal opgehaalde keren voor kleurcodering
            $maxTotaal = !empty($totaalPerCertificaat) ? max($totaalPerCertificaat) : 0;

            // Haal rapportgegevens op voor elke geselecteerde datum
            $rapportGegevens = [];
            foreach ($geselecteerdeUitgiftedatumIds as $datumId) {
                $rapportGegevens[$datumId] = getRapportGegevens($db, $datumId);
            }
        }
    }
    elseif (isset($_POST['selecteer_alles'])) {
        $geselecteerdeUitgiftedatumIds = array_column($uitgiftedata, 'id');
        $opgehaaldeData = getOpgehaaldeCertificatenPerDatum($db, $geselecteerdeUitgiftedatumIds);
        $productInfoPerCertificaat = getProductInfoPerCertificaat($db);
        $totaalPerCertificaat = getTotaalOpgehaaldPerCertificaat($db, $alleCertificaten, $geselecteerdeUitgiftedatumIds);
        $totaalPerDatum = getTotaalOpgehaaldPerDatum($db, $geselecteerdeUitgiftedatumIds);

        // Bepaal het maximum aantal opgehaalde keren voor kleurcodering
        $maxTotaal = !empty($totaalPerCertificaat) ? max($totaalPerCertificaat) : 0;

        // Haal rapportgegevens op voor elke geselecteerde datum
        $rapportGegevens = [];
        foreach ($geselecteerdeUitgiftedatumIds as $datumId) {
            $rapportGegevens[$datumId] = getRapportGegevens($db, $datumId);
        }
    }
}

// Als er geen maxTotaal is bepaald, doe dat nu
if (!isset($maxTotaal)) {
    $maxTotaal = !empty($totaalPerCertificaat) ? max($totaalPerCertificaat) : 0;
}
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Uitgifte Rapport</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        function toggleSection(sectionId) {
            const section = document.getElementById(sectionId);
            const button = document.querySelector(`button[data-target="${sectionId}"]`);

            if (section.style.display === 'none') {
                section.style.display = 'block';
                button.textContent = 'Verberg sectie';
            } else {
                section.style.display = 'none';
                button.textContent = 'Toon sectie';
            }
        }

        function toggleAllSections(show) {
            const buttons = document.querySelectorAll('[id^="toggle-button-"]');
            buttons.forEach(button => {
                const sectionId = button.dataset.target;
                const section = document.getElementById(sectionId);

                if (show) {
                    section.style.display = 'block';
                    button.textContent = 'Verberg sectie';
                } else {
                    section.style.display = 'none';
                    button.textContent = 'Toon sectie';
                }
            });
        }
    </script>
    <style>
        /* Basis stijlen */
        .matrix-table {
            border-collapse: collapse;
            width: 100%;
            table-layout: fixed;
        }

        .matrix-table th,
        .matrix-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: center;
            word-break: break-word;
        }

        .matrix-table th:first-child,
        .matrix-table td:first-child {
            text-align: left;
            min-width: 120px;
            width: 120px;
        }

        .matrix-table th:nth-child(2),
        .matrix-table td:nth-child(2) {
            min-width: 80px;
            width: 80px;
            text-align: center;
        }

        .matrix-cell {
            min-width: 50px;
            height: 50px;
            font-weight: bold;
            font-size: 1.2rem;
            line-height: 1.2;
            vertical-align: middle;
        }

        .matrix-cell.opgehaald {
            background-color: #d1fae5;
        }

        .matrix-cell.niet-opgehaald {
            background-color: #fecaca;
        }

        .totaal-cell {
            font-weight: bold;
            font-size: 0.9rem;
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            min-width: 30px;
        }

        .tooltip {
            position: relative;
            display: inline-block;
            cursor: help;
        }

        .tooltip .tooltiptext {
            visibility: hidden;
            width: 200px;
            background-color: #555;
            color: #fff;
            text-align: left;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
        }

        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }

        .certificaat-info {
            font-size: 0.8rem;
            line-height: 1.2;
            text-align: left;
        }

        .totaal-rij {
            background-color: #f3f4f6;
            font-weight: bold;
        }

        .hidden {
            display: none;
        }

        @media print {
            .no-print {
                display: none !important;
            }

            .matrix-table {
                page-break-inside: auto;
            }

            tr {
                page-break-inside: avoid;
                page-break-after: auto;
            }
        }

        /* Specifieke stijl voor datum headers */
        .date-header {
            white-space: normal;
            min-width: 80px;
            writing-mode: horizontal-tb;
            text-orientation: initial;
        }
    </style>
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
    <div class="container w-full mx-auto pt-10 pb-10">
        <div class="w-full px-4 text-xl text-gray-800 leading-normal">
            <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
                <h1 class="text-2xl font-bold mb-6">Product Uitgifte Rapport</h1>

                <!-- Datum selectie formulier -->
                <form method="POST" action="" class="mb-6 p-4 border rounded-lg bg-gray-50 no-print">
                    <div class="mb-4">
                        <label class="block text-gray-700 text-sm font-bold mb-2">
                            Selecteer uitgiftedata voor rapport (van oud naar nieuw, alleen met transacties)
                        </label>
                        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2 mb-4 max-h-64 overflow-y-auto border p-2 rounded">
                            <?php foreach ($uitgiftedata as $datum):
                                $formattedDate = date('d-m-Y', strtotime($datum['uitgiftedatum']));
                            ?>
                                <div class="flex items-center">
                                    <input type="checkbox" id="datum_<?php echo $datum['id']; ?>"
                                           name="uitgiftedatum_ids[]" value="<?php echo $datum['id']; ?>"
                                           class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                                           <?php echo in_array($datum['id'], $geselecteerdeUitgiftedatumIds) ? 'checked' : ''; ?>>
                                    <label for="datum_<?php echo $datum['id']; ?>" class="ml-2 block text-sm text-gray-700 truncate">
                                        <?php echo $formattedDate; ?>
                                    </label>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-2 items-center">
                        <button type="submit" name="selecteer_datums"
                                class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                            Toon Geselecteerde Data
                        </button>
                        <button type="submit" name="selecteer_alles"
                                class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                            Selecteer Alle Data
                        </button>
                        <button type="button"
                                class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                                onclick="window.print()">
                            Print Rapport
                        </button>
                    </div>
                </form>

                <!-- Legenda -->
                <?php if (!empty($opgehaaldeData)): ?>
                    <div class="mb-4 p-2 bg-gray-100 rounded no-print">
                        <div class="flex items-center mb-2">
                            <span class="inline-block w-4 h-4 bg-green-200 mr-2 align-middle"></span> Certificaat opgehaald &
                            <span class="inline-block w-4 h-4 bg-red-200 ml-2 mr-2 align-middle"></span> Certificaat niet opgehaald
                        </div>
                        <div class="flex items-center">
                            <span class="inline-block w-4 h-4 bg-gray-200 mr-2 align-middle"></span> 0x &
                            <span class="inline-block w-4 h-4 bg-red-200 ml-2 mr-2 align-middle"></span> Laag &
                            <span class="inline-block w-4 h-4 bg-yellow-200 ml-2 mr-2 align-middle"></span> Medium &
                            <span class="inline-block w-4 h-4 bg-green-200 ml-2 mr-2 align-middle"></span> Hoog
                            <span class="ml-2 text-sm">(aantal keren opgehaald)</span>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- Matrix rapport -->
                <?php if (!empty($opgehaaldeData)): ?>
                    <!-- Matrix overzicht -->
                    <div class="mb-6">
                        <div class="flex justify-between items-center mb-2">
                            <h2 class="text-xl font-bold">Certificaten Uitgifte Matrix (Max opgehaald: <?php echo $maxTotaal; ?>)</h2>
                            <button id="toggle-button-matrix"
                                    class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-1 px-3 rounded text-sm focus:outline-none focus:shadow-outline"
                                    data-target="matrix-section"
                                    onclick="toggleSection('matrix-section')">
                                Verberg sectie
                            </button>
                        </div>
                        <div id="matrix-section" class="border rounded p-4">
                            <div class="overflow-x-auto">
                                <table class="matrix-table">
                                    <thead>
                                        <tr>
                                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-700 uppercase border">
                                                Certificaat
                                            </th>
                                            <th class="px-3 py-3 text-center text-xs font-medium text-gray-700 uppercase border">
                                                Totaal opgehaald
                                            </th>
                                            <?php
                                            // Sorteer de geselecteerde datums van oud naar nieuw voor weergave
                                            usort($geselecteerdeUitgiftedatumIds, function($a, $b) use ($uitgiftedata) {
                                                $datumA = array_filter($uitgiftedata, fn($d) => $d['id'] == $a);
                                                $datumB = array_filter($uitgiftedata, fn($d) => $d['id'] == $b);
                                                $datumA = reset($datumA);
                                                $datumB = reset($datumB);
                                                return strtotime($datumA['uitgiftedatum']) - strtotime($datumB['uitgiftedatum']);
                                            });

                                            foreach ($geselecteerdeUitgiftedatumIds as $datumId):
                                                $datumInfo = array_filter($uitgiftedata, fn($d) => $d['id'] == $datumId);
                                                $datumInfo = reset($datumInfo);
                                            ?>
                                                <th class="date-header px-3 py-3 text-xs font-medium text-gray-700 uppercase border">
                                                    <?php echo date('d-m-Y', strtotime($datumInfo['uitgiftedatum'])); ?>
                                                </th>
                                            <?php endforeach; ?>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Totaalrij -->
                                        <tr class="totaal-rij">
                                            <td class="px-3 py-2 border text-sm font-bold text-gray-900">
                                                Totaal per datum
                                            </td>
                                            <td class="px-3 py-2 border text-sm font-bold text-gray-900">
                                                -
                                            </td>
                                            <?php foreach ($geselecteerdeUitgiftedatumIds as $datumId): ?>
                                                <td class="px-3 py-2 border text-sm font-bold text-gray-900">
                                                    <?php echo $totaalPerDatum[$datumId] ?? 0; ?>
                                                </td>
                                            <?php endforeach; ?>
                                        </tr>

                                        <!-- Certificaatrijen -->
                                        <?php foreach ($alleCertificaten as $certificaat):
                                            $totaalOpgehaald = $totaalPerCertificaat[$certificaat] ?? 0;
                                        ?>
                                            <tr>
                                                <td class="px-3 py-2 border text-sm font-medium text-gray-900">
                                                    <div class="tooltip">
                                                        <?php echo $certificaat; ?>
                                                        <?php if (isset($productInfoPerCertificaat[$certificaat])): ?>
                                                            <span class="tooltiptext certificaat-info">
                                                                <?php echo str_replace(',', '<br>', $productInfoPerCertificaat[$certificaat]); ?>
                                                            </span>
                                                        <?php endif; ?>
                                                    </div>
                                                </td>
                                                <td class="px-3 py-2 border">
                                                    <div class="totaal-cell <?php echo getKleurOpBasisVanPercentage($totaalOpgehaald, $maxTotaal); ?>">
                                                        <?php echo $totaalOpgehaald; ?>
                                                    </div>
                                                </td>
                                                <?php foreach ($geselecteerdeUitgiftedatumIds as $datumId): ?>
                                                    <td class="matrix-cell border
                                                        <?php echo in_array($certificaat, $opgehaaldeData[$datumId] ?? []) ? 'opgehaald' : 'niet-opgehaald'; ?>">
                                                        <?php echo in_array($certificaat, $opgehaaldeData[$datumId] ?? []) ? '✓' : ''; ?>
                                                    </td>
                                                <?php endforeach; ?>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Gedetailleerde rapporten per datum -->
                    <?php foreach ($rapportGegevens as $datumId => $gegevens): ?>
                        <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
                            <div class="flex justify-between items-center mb-4 border-b pb-2">
                                <h2 class="text-xl font-bold">
                                    Gedetailleerd Rapport voor <?php echo date('d-m-Y', strtotime($gegevens['uitgiftedatumInfo']['uitgiftedatum'])); ?>
                                </h2>
                                <button id="toggle-button-<?php echo $datumId; ?>"
                                        class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-1 px-3 rounded text-sm focus:outline-none focus:shadow-outline"
                                        data-target="datum-section-<?php echo $datumId; ?>"
                                        onclick="toggleSection('datum-section-<?php echo $datumId; ?>')">
                                    Verberg sectie
                                </button>
                            </div>

                            <div id="datum-section-<?php echo $datumId; ?>">
                                <!-- Basis informatie -->
                                <div class="mb-4">
                                    <p><strong>Tijdstip:</strong>
                                        <?php echo date('H:i', strtotime($gegevens['uitgiftedatumInfo']['starttijd'])); ?> -
                                        <?php echo date('H:i', strtotime($gegevens['uitgiftedatumInfo']['eindtijd'])); ?>
                                    </p>
                                    <p><strong>Totaal aantal certificaten:</strong> <?php echo $gegevens['totalCertificaten']; ?></p>
                                    <p><strong>Totaal aantal monden:</strong> <?php echo $gegevens['totalMonden']; ?></p>
                                </div>

                                <!-- Registraties overzicht -->
                                <div class="mb-6">
                                    <div class="flex justify-between items-center mb-2">
                                        <h3 class="text-lg font-bold">Registraties (<?php echo count($gegevens['registraties']); ?>)</h3>
                                        <button id="toggle-button-registraties-<?php echo $datumId; ?>"
                                                class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-1 px-3 rounded text-sm focus:outline-none focus:shadow-outline"
                                                data-target="registraties-section-<?php echo $datumId; ?>"
                                                onclick="toggleSection('registraties-section-<?php echo $datumId; ?>')">
                                            Verberg sectie
                                        </button>
                                    </div>
                                    <div id="registraties-section-<?php echo $datumId; ?>" class="border rounded p-4">
                                        <table class="min-w-full divide-y divide-gray-200">
                                            <thead class="bg-gray-50">
                                                <tr>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Tijdstip</th>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Certificaat</th>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Product</th>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Monden</th>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Geregistreerd door</th>
                                                </tr>
                                            </thead>
                                            <tbody class="bg-white divide-y divide-gray-200">
                                                <?php foreach ($gegevens['registraties'] as $registratie): ?>
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <?php echo date('H:i:s', strtotime($registratie['registratie_tijd'])); ?>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                            <?php echo $registratie['certificaat']; ?>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <?php echo $registratie['product']; ?>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <?php echo $registratie['monden']; ?>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <?php echo $registratie['gebruiker']; ?>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                <!-- Niet opgehaalde certificaten -->
                                <div class="mb-6">
                                    <div class="flex justify-between items-center mb-2">
                                        <h3 class="text-lg font-bold">Niet opgehaalde certificaten (<?php echo count($gegevens['nietOpgehaaldeCertificaten']); ?>)</h3>
                                        <button id="toggle-button-niet-opgehaald-<?php echo $datumId; ?>"
                                                class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-1 px-3 rounded text-sm focus:outline-none focus:shadow-outline"
                                                data-target="niet-opgehaald-section-<?php echo $datumId; ?>"
                                                onclick="toggleSection('niet-opgehaald-section-<?php echo $datumId; ?>')">
                                            Verberg sectie
                                        </button>
                                    </div>
                                    <div id="niet-opgehaald-section-<?php echo $datumId; ?>" class="border rounded p-4">
                                        <table class="min-w-full divide-y divide-gray-200">
                                            <thead class="bg-gray-50">
                                                <tr>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Certificaat</th>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Product</th>
                                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Monden</th>
                                                </tr>
                                            </thead>
                                            <tbody class="bg-white divide-y divide-gray-200">
                                                <?php foreach ($gegevens['nietOpgehaaldeCertificaten'] as $certificaat): ?>
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                            <?php echo $certificaat['certificaat']; ?>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <?php echo $certificaat['product']; ?>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <?php echo $certificaat['monden']; ?>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div class="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded relative" role="alert">
                        <strong class="font-bold">Geen gegevens beschikbaar</strong>
                        <span class="block sm:inline">Selecteer een of meerdere uitgiftedata om het rapport te genereren.</span>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>
