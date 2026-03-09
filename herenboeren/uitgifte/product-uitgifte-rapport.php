<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';
require_once 'product-functions.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

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

$paginaTitel = "Product Uitgifte Rapport";
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $paginaTitel; ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script>
        function deselecteerAlleDatums() {
            const checkboxes = document.querySelectorAll('input[name="uitgiftedatum_ids[]"]');
            checkboxes.forEach(checkbox => {
                checkbox.checked = false;
            });
            return false; // Voorkom form submit
        }

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
            <div class="bg-white shadow-md rounded px-8 pt-6 pb-4 mb-2">

                <!-- Terugknop en gebruikersinformatie -->
                <div class="flex flex-col md:flex-row justify-between items-center mb-6">
                    <div class="w-full md:w-auto mb-4 md:mb-0">
                      <a href="<?php echo $indexFile; ?>" class="inline-block bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded mb-4 md:mb-0 focus:outline-none focus:shadow-outline">
                        <i class="fas fa-arrow-left mr-2"></i>Terug naar Overzicht
                      </a>
                </div>

                <div class="w-full md:w-auto text-center md:text-right">
                    <h1 class="text-2xl font-bold mb-2"><?php echo $paginaTitel; ?></h1>
                    <p class="text-gray-700"><i class="fas fa-user mr-2"></i>Ingelogd als: <span class="font-semibold"><?php echo htmlspecialchars(getGebruikersnaam()); ?></span></p>
                    <p class="text-sm text-gray-500"><?php echo date('d-m-Y H:i'); ?></p>
                </div>
            </div>
        </div>
    </div>

    <div class="container w-full mx-auto pt-0">
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
                                class="bg-orange-500 hover:bg-orange-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                                onclick="deselecteerAlleDatums()">
                            Deselecteer Alles
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
                                            <?php if ($toonNamen): ?>
                                                <th class="px-3 py-3 text-left text-xs font-medium text-gray-700 uppercase border">
                                                    Naam
                                                </th>
                                            <?php endif; ?>
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
                                            <?php if ($toonNamen): ?>
                                                <td class="px-3 py-2 border text-sm font-bold text-gray-900">
                                                    -
                                                </td>
                                            <?php endif; ?>
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
                                            $totaalOpgehaald = $totaalPerCertificaat[$certificaat['leden_id']] ?? 0;
                                            $certInfo = $productInfoPerCertificaat[$certificaat['leden_id']] ?? [];
                                        ?>
                                            <tr>
                                                <td class="px-3 py-2 border text-sm font-medium text-gray-900">
                                                    <div class="tooltip">
                                                        <?php echo $certificaat['certificaat']; ?>
                                                        <?php if (isset($certInfo['producten'])): ?>
                                                            <span class="tooltiptext certificaat-info">
                                                                <?php echo str_replace(',', '<br>', $certInfo['producten']); ?>
                                                            </span>
                                                        <?php endif; ?>
                                                    </div>
                                                </td>
                                                <?php if ($toonNamen): ?>
                                                    <td class="px-3 py-2 border text-sm text-gray-900">
                                                        <?php echo $certInfo['naam'] ?? '-'; ?>
                                                    </td>
                                                <?php endif; ?>
                                                <td class="px-3 py-2 border">
                                                    <div class="totaal-cell <?php echo getKleurOpBasisVanPercentage($totaalOpgehaald, $maxTotaal); ?>">
                                                        <?php echo $totaalOpgehaald; ?>
                                                    </div>
                                                </td>
                                                <?php foreach ($geselecteerdeUitgiftedatumIds as $datumId): ?>
                                                    <td class="matrix-cell border
                                                        <?php echo in_array($certificaat['leden_id'], $opgehaaldeData[$datumId] ?? []) ? 'opgehaald' : 'niet-opgehaald'; ?>">
                                                        <?php echo in_array($certificaat['leden_id'], $opgehaaldeData[$datumId] ?? []) ? '✓' : ''; ?>
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
                                                    <?php if ($toonNamen): ?>
                                                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Naam</th>
                                                    <?php endif; ?>
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
                                                        <?php if ($toonNamen): ?>
                                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                                <?php echo $registratie['lid_naam'] ?? '-'; ?>
                                                            </td>
                                                        <?php endif; ?>
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
                                                    <?php if ($toonNamen): ?>
                                                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Naam</th>
                                                    <?php endif; ?>
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
                                                        <?php if ($toonNamen): ?>
                                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                                <?php echo $certificaat['lid_naam'] ?? '-'; ?>
                                                            </td>
                                                        <?php endif; ?>
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
