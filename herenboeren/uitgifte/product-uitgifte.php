<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';
require_once 'product-functions.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Controleer of de uitgifte open is
$uitgifteOpen = isUitgifteOpen($db);

// Haal certificaten die nog niet hebben opgehaald op voor de dropdown
$nogNietOpgehaaldeCertificatenVoorDropdown = [];
if ($uitgifteOpen) {
    $nogNietOpgehaaldeCertificatenVoorDropdown = getNogNietOpgehaaldeCertificaten($db);
}

// Verwerk het registratieformulier
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['submit'])) {
        $certificaat = $_POST['certificaat'];

        if ($uitgifteOpen) {
            $result = registreerCertificaat($db, $certificaat);
            if ($result === "certificaat_bestaat_niet") {
                $error = "Fout: Certificaatnummer bestaat niet.";
            } elseif (!$result) {
                $error = "Dit certificaat is vandaag al geregistreerd.";
            }
        }
        // Vernieuw de lijst met nog niet opgehaalde certificaten na registratie
        $nogNietOpgehaaldeCertificatenVoorDropdown = getNogNietOpgehaaldeCertificaten($db);
    } elseif (isset($_POST['undo'])) {
        $success = verwijderLaatsteRegistratie($db);
        if ($success) {
            $undoSuccess = "Laatste registratie is verwijderd.";
        } else {
            $undoError = "Kon laatste registratie niet verwijderen.";
        }
        // Vernieuw de lijst met nog niet opgehaalde certificaten na undo
        $nogNietOpgehaaldeCertificatenVoorDropdown = getNogNietOpgehaaldeCertificaten($db);
    }
}

// Haal statistieken, nog niet opgehaalde certificaten en producten op
$statistieken = getStatistieken($db);
$nogNietOpgehaaldeCertificaten = getNogNietOpgehaaldeCertificaten($db);
$nietOpgehaaldeProductenPerProduct = getNietOpgehaaldeProductenPerProduct($db);
$totaalNietOpgehaaldeProducten = getTotaalNietOpgehaaldeProducten($db);
$producten = getProducten($db);
$productStatistieken = getProductStatistieken($db);
$laatsteRegistratie = getLaatsteRegistratie($db);

$paginaTitel = "Product Uitgifte";
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $paginaTitel; ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">

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
            <?php if (!$uitgifteOpen): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                    <strong class="font-bold">Uitgifte gesloten</strong>
                </div>
            <?php else: ?>
                <!-- Registratie Formulier -->
                <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
                    <h1 class="text-2xl font-bold mb-4">Product Uitgifte</h1>
                    <?php if (isset($error)): ?>
                        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                            <span class="block sm:inline"><?php echo $error; ?></span>
                        </div>
                    <?php endif; ?>
                    <form method="POST" action="" class="space-y-4">
                        <div>
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="certificaat">
                                Certificaatnummer
                            </label>
                            <input type="number" id="certificaat" name="certificaat" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline <?php echo $inputFontSize; ?>" placeholder="Voer certificaatnummer in" required>
                        </div>
                        <div>
                            <label class="block text-gray-700 text-sm font-bold mb-2">
                                Of kies uit certificaten die nog niet hebben opgehaald:
                            </label>
                            <select id="certificatenDropdown" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline <?php echo $inputFontSize; ?>"
                                    onchange="document.getElementById('certificaat').value = this.value">
                                <option value="">Selecteer een certificaat</option>
                                <?php foreach ($nogNietOpgehaaldeCertificatenVoorDropdown as $certificaat): ?>
                                    <option value="<?php echo $certificaat['certificaat']; ?>">
                                        <?php echo $certificaat['certificaat']; ?> -
                                        <?php if ($toonNamen && !empty($certificaat['lid_naam'])): ?>
                                            <?php echo htmlspecialchars($certificaat['lid_naam']); ?> -
                                        <?php endif; ?>
                                        <?php echo htmlspecialchars($certificaat['product']); ?> (
                                        <?php echo $certificaat['monden']; ?>
                                        <?php echo $certificaat['monden'] == 1 ? 'mond' : 'monden'; ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="flex items-center justify-between">
                            <button class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="submit" name="submit">
                                Registreer
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Laatste Registratie -->
                <?php if (isset($laatsteRegistratie)): ?>
                    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative mb-4" role="alert">
                        <h2 class="text-lg font-bold mb-2">Laatste Registratie</h2>
                        <p><strong>Certificaatnummer:</strong> <?php echo $laatsteRegistratie['certificaat']; ?></p>
                        <?php if ($toonNamen && isset($laatsteRegistratie['lid_naam'])): ?>
                            <p><strong>Naam:</strong> <?php echo $laatsteRegistratie['lid_naam']; ?></p>
                        <?php endif; ?>
                        <p><strong>Geregistreerd door:</strong> <?php echo $laatsteRegistratie['gebruiker']; ?></p>
                        <p><strong>Product:</strong> <?php echo $laatsteRegistratie['product']; ?></p>
                        <p><strong>Monden:</strong> <?php echo $laatsteRegistratie['monden']; ?></p>
                        <p><strong>Registratie Tijd:</strong> <?php echo $laatsteRegistratie['registratie_tijd']; ?></p>
                        <form method="POST" action="" class="mt-4">
                            <button class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="submit" name="undo">
                                Undo
                            </button>
                        </form>
                        <?php if (isset($undoSuccess)): ?>
                            <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative mt-4" role="alert">
                                <span class="block sm:inline"><?php echo $undoSuccess; ?></span>
                            </div>
                        <?php endif; ?>
                        <?php if (isset($undoError)): ?>
                            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mt-4" role="alert">
                                <span class="block sm:inline"><?php echo $undoError; ?></span>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <!-- Overzichtsscherm -->
                <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
                    <h1 class="text-2xl font-bold mb-4">Overzicht (Vandaag)</h1>

                    <!-- Tabel met productstatistieken -->
                    <div class="mt-6">
                        <h2 class="text-xl font-bold mb-4">Overzicht per Product</h2>
                        <table class="min-w-full divide-y divide-gray-200 border border-gray-300">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Product</th>
                                    <?php foreach ($producten as $product): ?>
                                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border"><?php echo $product['naam']; ?></th>
                                    <?php endforeach; ?>
                                    <?php if ($showTotalColumn): ?>
                                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Totaal</th>
                                    <?php endif; ?>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
                                <!-- Nog op te halen sectie -->
                                <tr class="section-red">
                                    <td class="px-6 py-3 text-left text-sm font-bold text-gray-900 border">Nog op te halen</td>
                                    <?php
                                    $totaalNietOpgehaaldCertificaten = 0;
                                    $totaalNietOpgehaaldMonden = 0;
                                    ?>
                                    <?php foreach ($producten as $product): ?>
                                        <?php
                                        $productNaam = $product['naam'];
                                        $stats = $productStatistieken[$productNaam];
                                        $aantalCertificaten = $stats['niet_opgehaald_certificaten'];
                                        $aantalMonden = $stats['niet_opgehaald_monden'];
                                        $percentageCertificaten = $stats['percentage_niet_opgehaald_certificaten'];
                                        $percentageMonden = $stats['percentage_niet_opgehaald_monden'];
                                        $totaalNietOpgehaaldCertificaten += $aantalCertificaten;
                                        $totaalNietOpgehaaldMonden += $aantalMonden;
                                        ?>
                                        <td class="px-6 py-3 text-left text-sm text-gray-500 border">
                                            <?php echo $aantalCertificaten; ?> certificaten (<?php echo $percentageCertificaten; ?>%)<br>
                                            <?php echo $aantalMonden; ?> monden (<?php echo $percentageMonden; ?>%)
                                        </td>
                                    <?php endforeach; ?>
                                    <?php if ($showTotalColumn): ?>
                                        <td class="px-6 py-3 text-left text-sm text-gray-500 border font-bold">
                                            <?php
                                            $totaalPercentageCertificaten = $productStatistieken['totaal']['percentage_niet_opgehaald_certificaten'];
                                            $totaalPercentageMonden = $productStatistieken['totaal']['percentage_niet_opgehaald_monden'];
                                            ?>
                                            <?php echo $totaalNietOpgehaaldCertificaten; ?> certificaten (<?php echo $totaalPercentageCertificaten; ?>%)<br>
                                            <?php echo $totaalNietOpgehaaldMonden; ?> monden (<?php echo $totaalPercentageMonden; ?>%)
                                        </td>
                                    <?php endif; ?>
                                </tr>
                                <!-- Opgehaald sectie -->
                                <tr class="section-green">
                                    <td class="px-6 py-3 text-left text-sm font-bold text-gray-900 border">Opgehaald</td>
                                    <?php
                                    $totaalOpgehaaldCertificaten = 0;
                                    $totaalOpgehaaldMonden = 0;
                                    ?>
                                    <?php foreach ($producten as $product): ?>
                                        <?php
                                        $productNaam = $product['naam'];
                                        $stats = $productStatistieken[$productNaam];
                                        $aantalCertificaten = $stats['opgehaald_certificaten'];
                                        $aantalMonden = $stats['opgehaald_monden'];
                                        $percentageCertificaten = $stats['percentage_opgehaald_certificaten'];
                                        $percentageMonden = $stats['percentage_opgehaald_monden'];
                                        $totaalOpgehaaldCertificaten += $aantalCertificaten;
                                        $totaalOpgehaaldMonden += $aantalMonden;
                                        ?>
                                        <td class="px-6 py-3 text-left text-sm text-gray-500 border">
                                            <?php echo $aantalCertificaten; ?> certificaten (<?php echo $percentageCertificaten; ?>%)<br>
                                            <?php echo $aantalMonden; ?> monden (<?php echo $percentageMonden; ?>%)
                                        </td>
                                    <?php endforeach; ?>
                                    <?php if ($showTotalColumn): ?>
                                        <td class="px-6 py-3 text-left text-sm text-gray-500 border font-bold">
                                            <?php
                                            $totaalPercentageCertificaten = $productStatistieken['totaal']['percentage_opgehaald_certificaten'];
                                            $totaalPercentageMonden = $productStatistieken['totaal']['percentage_opgehaald_monden'];
                                            ?>
                                            <?php echo $totaalOpgehaaldCertificaten; ?> certificaten (<?php echo $totaalPercentageCertificaten; ?>%)<br>
                                            <?php echo $totaalOpgehaaldMonden; ?> monden (<?php echo $totaalPercentageMonden; ?>%)
                                        </td>
                                    <?php endif; ?>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

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
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
