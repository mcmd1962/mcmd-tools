<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Functie om de gebruikersnaam op te halen
function getGebruikersnaam() {
    $username = '';
    // Try to get the login name from the $_SERVER variable.
    if (isset($_SERVER['HTTP_AUTHORIZATION']) || isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        $authorization_header = '';
        if (isset($_SERVER['HTTP_AUTHORIZATION']) && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorization_header = $_SERVER['HTTP_AUTHORIZATION'];
        }
        // If using CGI on Apache with mod_rewrite, the forwarded HTTP header appears in the redirected HTTP headers.
        elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) && !empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $authorization_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }
        // Resemble PHP_AUTH_USER and PHP_AUTH_PW for a Basic authentication from
        // the HTTP_AUTHORIZATION header. See http://www.php.net/manual/features.http-auth.php
        if (!empty($authorization_header)) {
            list($username_temp, $userpass_temp) = explode(':', base64_decode(substr($authorization_header, 6)));
            $username = $username_temp;
        }
    }
    // Check other possible values in different keys of the $_SERVER superglobal
    elseif (isset($_SERVER['REDIRECT_REMOTE_USER'])) {
        $username = $_SERVER['REDIRECT_REMOTE_USER'];
    }
    elseif (isset($_SERVER['REMOTE_USER'])) {
        $username = $_SERVER['REMOTE_USER'];
    }
    elseif (isset($_SERVER['REDIRECT_PHP_AUTH_USER'])) {
        $username = $_SERVER['REDIRECT_PHP_AUTH_USER'];
    }
    elseif (isset($_SERVER['PHP_AUTH_USER'])) {
        $username = $_SERVER['PHP_AUTH_USER'];
    }

    // Als er geen gebruikersnaam gevonden is, gebruik dan 'Anoniem'
    return !empty($username) ? $username : 'Anoniem';
}

// Functie om een audit log te schrijven
function logAction($actionType, $details) {
    global $logFile;
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $gebruikersnaam = getGebruikersnaam();
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] IP: $ipAddress, Gebruiker: $gebruikersnaam, Actie: $actionType, Details: $details\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

// Functie om de huidige uitgiftedag op te halen of aan te maken
function getHuidigeUitgiftedag($db) {
    $vandaag = date('Y-m-d');

    $stmt = $db->prepare("SELECT id, uitgiftedatum, starttijd, eindtijd FROM uitgiftedatum WHERE uitgiftedatum = :vandaag");
    $stmt->bindValue(':vandaag', $vandaag, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        return $row;
    } else {
        $starttijd = date('H:i:s');
        $eindtijd = date('H:i:s', strtotime('+4 hours'));
        $id = voegUitgiftedatumToe($db, $vandaag, $starttijd, $eindtijd);
        return [
            'id' => $id,
            'uitgiftedatum' => $vandaag,
            'starttijd' => $starttijd,
            'eindtijd' => $eindtijd
        ];
    }
}

// Functie om een uitgiftedatum toe te voegen
function voegUitgiftedatumToe($db, $uitgiftedatum, $starttijd, $eindtijd) {
    $stmt = $db->prepare("INSERT INTO uitgiftedatum (uitgiftedatum, starttijd, eindtijd) VALUES (:uitgiftedatum, :starttijd, :eindtijd)");
    $stmt->bindValue(':uitgiftedatum', $uitgiftedatum, SQLITE3_TEXT);
    $stmt->bindValue(':starttijd', $starttijd, SQLITE3_TEXT);
    $stmt->bindValue(':eindtijd', $eindtijd, SQLITE3_TEXT);

    try {
        $stmt->execute();
        $uitgiftedatumId = $db->lastInsertRowID();
        logAction('UITGIFTEDATUM_TOEGEVOEGD', "Uitgiftedatum toegevoegd: $uitgiftedatum (ID: $uitgiftedatumId)");
        return $uitgiftedatumId;
    } catch (Exception $e) {
        logAction('UITGIFTEDATUM_FOUT', "Fout bij toevoegen uitgiftedatum: $uitgiftedatum, Error: " . $e->getMessage());
        return false;
    }
}

// Functie om te controleren of de huidige datum en tijd binnen een uitgiftedatum valt
function isUitgifteOpen($db) {
    $nu = new DateTime();
    $huidigeDatum = $nu->format('Y-m-d');
    $huidigeTijd = $nu->format('H:i:s');

    $stmt = $db->prepare("
        SELECT id, uitgiftedatum, starttijd, eindtijd
        FROM uitgiftedatum
        WHERE uitgiftedatum = :huidigeDatum
        AND :huidigeTijd BETWEEN starttijd AND eindtijd
    ");
    $stmt->bindValue(':huidigeDatum', $huidigeDatum, SQLITE3_TEXT);
    $stmt->bindValue(':huidigeTijd', $huidigeTijd, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    return $row !== false;
}

// Functie om te controleren of een certificaat bestaat
function certificaatBestaat($db, $certificaat) {
    $stmt = $db->prepare("SELECT certificaat FROM leden WHERE certificaat = :certificaat");
    $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    return $row !== false;
}

// Functie om registratie toe te voegen
function registreerCertificaat($db, $certificaat) {
    if (!certificaatBestaat($db, $certificaat)) {
        logAction('REGISTRATIE_FOUT', "Certificaat $certificaat bestaat niet");
        return "certificaat_bestaat_niet";
    }

    $registratieTijd = date('Y-m-d H:i:s');
    $uitgiftedag = getHuidigeUitgiftedag($db);
    $gebruiker = getGebruikersnaam();

    $stmt = $db->prepare("
        SELECT certificaat
        FROM registraties
        WHERE certificaat = :certificaat AND uitgiftedag = :uitgiftedag
    ");
    $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        logAction('REGISTRATIE_DUBBEL', "Certificaat $certificaat is vandaag al geregistreerd");
        return false;
    }

    $stmt = $db->prepare("
        INSERT INTO registraties (certificaat, gebruiker, registratie_tijd, uitgiftedag)
        VALUES (:certificaat, :gebruiker, :registratie_tijd, :uitgiftedag)
    ");
    $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
    $stmt->bindValue(':gebruiker', $gebruiker, SQLITE3_TEXT);
    $stmt->bindValue(':registratie_tijd', $registratieTijd, SQLITE3_TEXT);
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);

    try {
        $stmt->execute();
        logAction('REGISTRATIE_TOEGEVOEGD', "Certificaat $certificaat geregistreerd door $gebruiker op " . $uitgiftedag['uitgiftedatum']);
        return true;
    } catch (Exception $e) {
        logAction('REGISTRATIE_FOUT', "Fout bij registreren certificaat $certificaat, Error: " . $e->getMessage());
        return false;
    }
}

// Functie om de laatste registratie te verwijderen
function verwijderLaatsteRegistratie($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $stmt = $db->prepare("
        SELECT id, certificaat, gebruiker FROM registraties
        WHERE id = (SELECT id FROM registraties WHERE uitgiftedag = :uitgiftedag ORDER BY id DESC LIMIT 1)
    ");
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        $laatsteId = $row['id'];
        $laatsteCertificaat = $row['certificaat'];
        $laatsteGebruiker = $row['gebruiker'];

        $stmt = $db->prepare("
            DELETE FROM registraties
            WHERE id = :id
        ");
        $stmt->bindValue(':id', $laatsteId, SQLITE3_INTEGER);

        try {
            $stmt->execute();
            logAction('REGISTRATIE_VERWIJDERD', "Registratie van certificaat $laatsteCertificaat door $laatsteGebruiker verwijderd");
            return true;
        } catch (Exception $e) {
            logAction('REGISTRATIE_VERWIJDER_FOUT', "Fout bij verwijderen registratie van certificaat $laatsteCertificaat, Error: " . $e->getMessage());
            return false;
        }
    } else {
        logAction('REGISTRATIE_VERWIJDER_FOUT', "Geen registraties om te verwijderen");
        return false;
    }
}

// Functie om de laatste registratie op te halen
function getLaatsteRegistratie($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $result = $db->query("
        SELECT registraties.certificaat, registraties.gebruiker, producten.naam as product, leden.monden, registraties.registratie_tijd
        FROM registraties
        JOIN leden ON registraties.certificaat = leden.certificaat
        JOIN producten ON leden.product_id = producten.id
        WHERE registraties.uitgiftedag = {$uitgiftedag['id']}
        ORDER BY registraties.id DESC
        LIMIT 1
    ");
    return $result->fetchArray(SQLITE3_ASSOC);
}

// Functie om statistieken op te halen voor vandaag
function getStatistieken($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $result = $db->query("SELECT COUNT(*) as totalPersonen FROM registraties WHERE uitgiftedag = {$uitgiftedag['id']}");
    $row = $result->fetchArray(SQLITE3_ASSOC);

    $statistieken = [
        'totalPersonen' => $row['totalPersonen'],
        'producten' => [],
        'totalHoeveelheid' => 0
    ];

    $productenResult = $db->query("SELECT id, naam FROM producten");
    while ($productRow = $productenResult->fetchArray(SQLITE3_ASSOC)) {
        $productId = $productRow['id'];
        $productNaam = $productRow['naam'];

        $countResult = $db->query("
            SELECT COUNT(*) as count, SUM(leden.monden) as totalHoeveelheid
            FROM registraties
            JOIN leden ON registraties.certificaat = leden.certificaat
            WHERE leden.product_id = $productId AND registraties.uitgiftedag = {$uitgiftedag['id']}
        ");
        $countRow = $countResult->fetchArray(SQLITE3_ASSOC);

        $statistieken['producten'][$productNaam] = [
            'aantal' => $countRow['count'],
            'hoeveelheid' => $countRow['totalHoeveelheid'] ?? 0
        ];
        $statistieken['totalHoeveelheid'] += $countRow['totalHoeveelheid'] ?? 0;
    }

    return $statistieken;
}

// Functie om alle certificaten op te halen
function getCertificaten($db) {
    $result = $db->query("SELECT certificaat, product_id, monden FROM leden ORDER BY certificaat");
    $certificaten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $certificaten[$row['certificaat']] = $row;
    }
    return $certificaten;
}

// Functie om certificaten die nog niet hebben opgehaald vandaag op te halen
function getNogNietOpgehaaldeCertificaten($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $result = $db->query("
        SELECT leden.certificaat, producten.naam as product, leden.monden
        FROM leden
        JOIN producten ON leden.product_id = producten.id
        WHERE leden.certificaat NOT IN (
            SELECT certificaat
            FROM registraties
            WHERE uitgiftedag = {$uitgiftedag['id']}
        )
        ORDER BY leden.certificaat
    ");
    $certificaten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $certificaten[] = $row;
    }
    return $certificaten;
}

// Functie om het totaal aantal niet-opgehaalde producten te berekenen
function getTotaalNietOpgehaaldeProducten($db) {
    $nogNietOpgehaaldeCertificaten = getNogNietOpgehaaldeCertificaten($db);
    $totaal = 0;
    foreach ($nogNietOpgehaaldeCertificaten as $certificaat) {
        $totaal += $certificaat['monden'];
    }
    return $totaal;
}

// Functie om het aantal niet-opgehaalde producten per product te berekenen
function getNietOpgehaaldeProductenPerProduct($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);
    $nietOpgehaaldeProducten = [];

    $productenResult = $db->query("SELECT id, naam FROM producten");
    while ($productRow = $productenResult->fetchArray(SQLITE3_ASSOC)) {
        $productId = $productRow['id'];
        $productNaam = $productRow['naam'];

        $result = $db->query("
            SELECT SUM(leden.monden) as totalHoeveelheid
            FROM leden
            JOIN producten ON leden.product_id = producten.id
            WHERE leden.certificaat NOT IN (
                SELECT certificaat
                FROM registraties
                WHERE uitgiftedag = {$uitgiftedag['id']}
            )
            AND leden.product_id = $productId
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);

        $nietOpgehaaldeProducten[$productNaam] = $row['totalHoeveelheid'] ?? 0;
    }

    return $nietOpgehaaldeProducten;
}

// Functie om de statistieken per product te berekenen
function getProductStatistieken($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);
    $producten = getProducten($db);

    $statistieken = [];
    $totaalNietOpgehaaldCertificaten = 0;
    $totaalOpgehaaldCertificaten = 0;
    $totaalNietOpgehaaldMonden = 0;
    $totaalOpgehaaldMonden = 0;
    $totaalCertificaten = 0;
    $totaalMonden = 0;

    foreach ($producten as $product) {
        $productId = $product['id'];
        $productNaam = $product['naam'];

        // Aantal certificaten dat dit product heeft
        $result = $db->query("SELECT COUNT(*) as count FROM leden WHERE product_id = $productId");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $totaalCertificatenProduct = $row['count'];
        $totaalCertificaten += $totaalCertificatenProduct;

        // Aantal certificaten dat dit product nog niet heeft opgehaald
        $result = $db->query("
            SELECT COUNT(*) as count
            FROM leden
            WHERE product_id = $productId
            AND certificaat NOT IN (
                SELECT certificaat FROM registraties WHERE uitgiftedag = {$uitgiftedag['id']}
            )
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $nietOpgehaaldCertificaten = $row['count'];
        $totaalNietOpgehaaldCertificaten += $nietOpgehaaldCertificaten;

        // Aantal certificaten dat dit product wel heeft opgehaald
        $opgehaaldCertificaten = $totaalCertificatenProduct - $nietOpgehaaldCertificaten;
        $totaalOpgehaaldCertificaten += $opgehaaldCertificaten;

        // Totaal aantal monden dat nog opgehaald moet worden
        $result = $db->query("
            SELECT SUM(monden) as totalHoeveelheid
            FROM leden
            WHERE product_id = $productId
            AND certificaat NOT IN (
                SELECT certificaat FROM registraties WHERE uitgiftedag = {$uitgiftedag['id']}
            )
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $nietOpgehaaldMonden = $row['totalHoeveelheid'] ?? 0;
        $totaalNietOpgehaaldMonden += $nietOpgehaaldMonden;

        // Totaal aantal monden dat al is opgehaald
        $result = $db->query("
            SELECT SUM(leden.monden) as totalHoeveelheid
            FROM registraties
            JOIN leden ON registraties.certificaat = leden.certificaat
            WHERE leden.product_id = $productId AND registraties.uitgiftedag = {$uitgiftedag['id']}
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $opgehaaldMonden = $row['totalHoeveelheid'] ?? 0;
        $totaalOpgehaaldMonden += $opgehaaldMonden;

        // Totaal aantal monden
        $result = $db->query("SELECT SUM(monden) as totalHoeveelheid FROM leden WHERE product_id = $productId");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $totaalMondenProduct = $row['totalHoeveelheid'] ?? 0;
        $totaalMonden += $totaalMondenProduct;

        // Bereken percentages
        $percentageOpgehaaldCertificaten = $totaalCertificatenProduct > 0 ? round(($opgehaaldCertificaten / $totaalCertificatenProduct) * 100, 1) : 0;
        $percentageNietOpgehaaldCertificaten = $totaalCertificatenProduct > 0 ? round(($nietOpgehaaldCertificaten / $totaalCertificatenProduct) * 100, 1) : 0;
        $percentageOpgehaaldMonden = $totaalMondenProduct > 0 ? round(($opgehaaldMonden / $totaalMondenProduct) * 100, 1) : 0;
        $percentageNietOpgehaaldMonden = $totaalMondenProduct > 0 ? round(($nietOpgehaaldMonden / $totaalMondenProduct) * 100, 1) : 0;

        $statistieken[$productNaam] = [
            'totaal_certificaten' => $totaalCertificatenProduct,
            'niet_opgehaald_certificaten' => $nietOpgehaaldCertificaten,
            'opgehaald_certificaten' => $opgehaaldCertificaten,
            'niet_opgehaald_monden' => $nietOpgehaaldMonden,
            'opgehaald_monden' => $opgehaaldMonden,
            'totaal_monden' => $totaalMondenProduct,
            'percentage_opgehaald_certificaten' => $percentageOpgehaaldCertificaten,
            'percentage_niet_opgehaald_certificaten' => $percentageNietOpgehaaldCertificaten,
            'percentage_opgehaald_monden' => $percentageOpgehaaldMonden,
            'percentage_niet_opgehaald_monden' => $percentageNietOpgehaaldMonden
        ];
    }

    // Bereken totalen
    $totaalPercentageOpgehaaldCertificaten = $totaalCertificaten > 0 ? round(($totaalOpgehaaldCertificaten / $totaalCertificaten) * 100, 1) : 0;
    $totaalPercentageNietOpgehaaldCertificaten = $totaalCertificaten > 0 ? round(($totaalNietOpgehaaldCertificaten / $totaalCertificaten) * 100, 1) : 0;
    $totaalPercentageOpgehaaldMonden = $totaalMonden > 0 ? round(($totaalOpgehaaldMonden / $totaalMonden) * 100, 1) : 0;
    $totaalPercentageNietOpgehaaldMonden = $totaalMonden > 0 ? round(($totaalNietOpgehaaldMonden / $totaalMonden) * 100, 1) : 0;

    $statistieken['totaal'] = [
        'totaal_certificaten' => $totaalCertificaten,
        'niet_opgehaald_certificaten' => $totaalNietOpgehaaldCertificaten,
        'opgehaald_certificaten' => $totaalOpgehaaldCertificaten,
        'niet_opgehaald_monden' => $totaalNietOpgehaaldMonden,
        'opgehaald_monden' => $totaalOpgehaaldMonden,
        'totaal_monden' => $totaalMonden,
        'percentage_opgehaald_certificaten' => $totaalPercentageOpgehaaldCertificaten,
        'percentage_niet_opgehaald_certificaten' => $totaalPercentageNietOpgehaaldCertificaten,
        'percentage_opgehaald_monden' => $totaalPercentageOpgehaaldMonden,
        'percentage_niet_opgehaald_monden' => $totaalPercentageNietOpgehaaldMonden
    ];

    return $statistieken;
}

// Functie om alle producten op te halen
function getProducten($db) {
    $result = $db->query("SELECT id, naam FROM producten");
    $producten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $producten[] = $row;
    }
    return $producten;
}

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
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Uitgifte</title>
    <script src="https://cdn.tailwindcss.com"></script>
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
    </style>
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
    <div class="container w-full mx-auto pt-20">
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
                            <select id="certificatenDropdown" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline <?php echo $inputFontSize; ?>" onchange="document.getElementById('certificaat').value = this.value">
                                <option value="">Selecteer een certificaat</option>
                                <?php foreach ($nogNietOpgehaaldeCertificatenVoorDropdown as $certificaat): ?>
                                    <option value="<?php echo $certificaat['certificaat']; ?>">
                                        <?php echo $certificaat['certificaat']; ?> - <?php echo $certificaat['product']; ?>
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
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Product</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border">Monden</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($nogNietOpgehaaldeCertificaten as $certificaat): ?>
                                <tr class="<?php echo ($certificaat['certificaat'] % 10 == 0) ? 'bg-gray-100' : ''; ?>">
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 border"><?php echo $certificaat['certificaat']; ?></td>
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
