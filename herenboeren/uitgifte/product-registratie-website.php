<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-registratie-config.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Functie om de gebruikersnaam op te halen
function getGebruikersnaam() {
    // return isset($_SESSION['gebruikersnaam']) ? $_SESSION['gebruikersnaam'] : 'Anoniem';
    $username = 'onbekend';
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
    return $username;
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

// Functie om een product toe te voegen
function voegProductToe($db, $naam) {
    $stmt = $db->prepare("INSERT INTO producten (naam) VALUES (:naam)");
    $stmt->bindValue(':naam', $naam, SQLITE3_TEXT);

    try {
        $stmt->execute();
        $productId = $db->lastInsertRowID();
        logAction('PRODUCT_TOEGEVOEGD', "Product toegevoegd: $naam (ID: $productId)");
        return $productId;
    } catch (Exception $e) {
        logAction('PRODUCT_FOUT', "Fout bij toevoegen product: $naam, Error: " . $e->getMessage());
        return false;
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

// Functie om een lid toe te voegen
function voegLidToe($db, $nummer, $product_id, $hoeveelheid) {
    $stmt = $db->prepare("INSERT INTO leden (nummer, product_id, hoeveelheid) VALUES (:nummer, :product_id, :hoeveelheid)");
    $stmt->bindValue(':nummer', $nummer, SQLITE3_INTEGER);
    $stmt->bindValue(':product_id', $product_id, SQLITE3_INTEGER);
    $stmt->bindValue(':hoeveelheid', $hoeveelheid, SQLITE3_INTEGER);

    try {
        $stmt->execute();
        logAction('LID_TOEGEVOEGD', "Lid toegevoegd: $nummer, Product ID: $product_id, Hoeveelheid: $hoeveelheid");
        return true;
    } catch (Exception $e) {
        logAction('LID_FOUT', "Fout bij toevoegen lid: $nummer, Error: " . $e->getMessage());
        return false;
    }
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

// Functie om te controleren of een lid bestaat
function lidBestaat($db, $nummer) {
    $stmt = $db->prepare("SELECT nummer FROM leden WHERE nummer = :nummer");
    $stmt->bindValue(':nummer', $nummer, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    return $row !== false;
}

// Functie om registratie toe te voegen
function registreerLid($db, $nummer) {
    if (!lidBestaat($db, $nummer)) {
        logAction('REGISTRATIE_FOUT', "Lid $nummer bestaat niet");
        return "lid_bestaat_niet";
    }

    $registratieTijd = date('Y-m-d H:i:s');
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $stmt = $db->prepare("
        SELECT nummer
        FROM registraties
        WHERE nummer = :nummer AND uitgiftedag = :uitgiftedag
    ");
    $stmt->bindValue(':nummer', $nummer, SQLITE3_INTEGER);
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        logAction('REGISTRATIE_DUBBEL', "Lid $nummer is vandaag al geregistreerd");
        return false;
    }

    $stmt = $db->prepare("
        INSERT INTO registraties (nummer, registratie_tijd, uitgiftedag)
        VALUES (:nummer, :registratie_tijd, :uitgiftedag)
    ");
    $stmt->bindValue(':nummer', $nummer, SQLITE3_INTEGER);
    $stmt->bindValue(':registratie_tijd', $registratieTijd, SQLITE3_TEXT);
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);

    try {
        $stmt->execute();
        logAction('REGISTRATIE_TOEGEVOEGD', "Lid $nummer geregistreerd op " . $uitgiftedag['uitgiftedatum']);
        return true;
    } catch (Exception $e) {
        logAction('REGISTRATIE_FOUT', "Fout bij registreren lid $nummer, Error: " . $e->getMessage());
        return false;
    }
}

// Functie om de laatste registratie te verwijderen
function verwijderLaatsteRegistratie($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $stmt = $db->prepare("
        SELECT id, nummer FROM registraties
        WHERE id = (SELECT id FROM registraties WHERE uitgiftedag = :uitgiftedag ORDER BY id DESC LIMIT 1)
    ");
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        $laatsteId = $row['id'];
        $laatsteNummer = $row['nummer'];

        $stmt = $db->prepare("
            DELETE FROM registraties
            WHERE id = :id
        ");
        $stmt->bindValue(':id', $laatsteId, SQLITE3_INTEGER);

        try {
            $stmt->execute();
            logAction('REGISTRATIE_VERWIJDERD', "Registratie van lid $laatsteNummer verwijderd");
            return true;
        } catch (Exception $e) {
            logAction('REGISTRATIE_VERWIJDER_FOUT', "Fout bij verwijderen registratie van lid $laatsteNummer, Error: " . $e->getMessage());
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
        SELECT registraties.nummer, producten.naam as product, leden.hoeveelheid, registraties.registratie_tijd
        FROM registraties
        JOIN leden ON registraties.nummer = leden.nummer
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
            SELECT COUNT(*) as count, SUM(leden.hoeveelheid) as totalHoeveelheid
            FROM registraties
            JOIN leden ON registraties.nummer = leden.nummer
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

// Functie om leden die nog niet hebben opgehaald vandaag op te halen
function getNogNietOpgehaaldeLeden($db, &$debugInfo) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $debugInfo = [
        'uitgiftedag' => $uitgiftedag,
        'query' => "
            SELECT leden.nummer, producten.naam as product, leden.hoeveelheid
            FROM leden
            JOIN producten ON leden.product_id = producten.id
            WHERE leden.nummer NOT IN (
                SELECT nummer
                FROM registraties
                WHERE uitgiftedag = {$uitgiftedag['id']}
            )
            ORDER BY leden.nummer
        "
    ];

    $result = $db->query($debugInfo['query']);
    $leden = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $leden[] = $row;
    }
    return $leden;
}

// Functie om het totaal aantal niet-opgehaalde producten te berekenen
function getTotaalNietOpgehaaldeProducten($db) {
    $nogNietOpgehaaldeLeden = getNogNietOpgehaaldeLeden($db, $debugInfo);
    $totaal = 0;
    foreach ($nogNietOpgehaaldeLeden as $lid) {
        $totaal += $lid['hoeveelheid'];
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
            SELECT SUM(leden.hoeveelheid) as totalHoeveelheid
            FROM leden
            JOIN producten ON leden.product_id = producten.id
            WHERE leden.nummer NOT IN (
                SELECT nummer
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

// Haal leden die nog niet hebben opgehaald op voor de dropdown
$nogNietOpgehaaldeLedenVoorDropdown = [];
if ($uitgifteOpen) {
    $uitgiftedag = getHuidigeUitgiftedag($db);
    $result = $db->query("
        SELECT leden.nummer, producten.naam as product, leden.hoeveelheid
        FROM leden
        JOIN producten ON leden.product_id = producten.id
        WHERE leden.nummer NOT IN (
            SELECT nummer
            FROM registraties
            WHERE uitgiftedag = {$uitgiftedag['id']}
        )
        ORDER BY leden.nummer
    ");
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $nogNietOpgehaaldeLedenVoorDropdown[] = $row;
    }
}

// Verwerk het registratieformulier
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['submit'])) {
        $nummer = $_POST['nummer'];

        if ($uitgifteOpen) {
            $result = registreerLid($db, $nummer);
            if ($result === "lid_bestaat_niet") {
                $error = "Fout: Lidnummer bestaat niet.";
            } elseif (!$result) {
                $error = "Deze persoon is vandaag al geregistreerd.";
            }
        }
    } elseif (isset($_POST['undo'])) {
        $success = verwijderLaatsteRegistratie($db);
        if ($success) {
            $undoSuccess = "Laatste registratie is verwijderd.";
        } else {
            $undoError = "Kon laatste registratie niet verwijderen.";
        }
    }
}

// Haal statistieken, nog niet opgehaalde leden en producten op
$statistieken = getStatistieken($db);
$debugInfo = [];
$nogNietOpgehaaldeLeden = getNogNietOpgehaaldeLeden($db, $debugInfo);
$nietOpgehaaldeProductenPerProduct = getNietOpgehaaldeProductenPerProduct($db);
$totaalNietOpgehaaldeProducten = getTotaalNietOpgehaaldeProducten($db);
$producten = getProducten($db);
$laatsteRegistratie = getLaatsteRegistratie($db);
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Registratie</title>
    <script src="https://cdn.tailwindcss.com"></script>
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
                    <h1 class="text-2xl font-bold mb-4">Product Registratie</h1>
                    <?php if (isset($error)): ?>
                        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                            <span class="block sm:inline"><?php echo $error; ?></span>
                        </div>
                    <?php endif; ?>
                    <form method="POST" action="" class="space-y-4">
                        <div>
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="nummer">
                                Lidnummer
                            </label>
                            <input type="number" id="nummer" name="nummer" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" placeholder="Voer lidnummer in" required>
                        </div>
                        <div>
                            <label class="block text-gray-700 text-sm font-bold mb-2">
                                Of kies uit leden die nog niet hebben opgehaald:
                            </label>
                            <select id="ledenDropdown" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" onchange="document.getElementById('nummer').value = this.value">
                                <option value="">Selecteer een lid</option>
                                <?php foreach ($nogNietOpgehaaldeLedenVoorDropdown as $lid): ?>
                                    <option value="<?php echo $lid['nummer']; ?>">
                                        <?php echo $lid['nummer']; ?> - <?php echo $lid['product']; ?>
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
                        <p><strong>Lidnummer:</strong> <?php echo $laatsteRegistratie['nummer']; ?></p>
                        <p><strong>Product:</strong> <?php echo $laatsteRegistratie['product']; ?></p>
                        <p><strong>Hoeveelheid:</strong> <?php echo $laatsteRegistratie['hoeveelheid']; ?></p>
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
                    <div class="space-y-4">
                        <p><strong>Aantal personen:</strong> <?php echo $statistieken['totalPersonen']; ?></p>
                        <p><strong>Aantal personen dat nog niet heeft opgehaald:</strong> <?php echo count($nogNietOpgehaaldeLeden); ?></p>
                        <p><strong>Totaal afgenomen producten:</strong> <?php echo $statistieken['totalHoeveelheid']; ?></p>
                        <p><strong>Totaal niet-opgehaalde producten:</strong> <?php echo $totaalNietOpgehaaldeProducten; ?></p>
                    </div>

                    <!-- Tabel met kolommen per product -->
                    <div class="mt-6">
                        <h2 class="text-xl font-bold mb-4">Overzicht per Product</h2>
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Product</th>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Aantal Afgenomen</th>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Totaal Afgenomen</th>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Niet Opgehaald</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
                                <?php foreach ($statistieken['producten'] as $product => $data): ?>
                                    <tr>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo $product; ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo $data['aantal']; ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo $data['hoeveelheid']; ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo $nietOpgehaaldeProductenPerProduct[$product] ?? 0; ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Nog Niet Opgehaalde Leden Overzicht -->
                <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
                    <h1 class="text-2xl font-bold mb-4">Leden die vandaag nog niet hebben opgehaald</h1>
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Nummer</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Product</th>
                                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Hoeveelheid</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php foreach ($nogNietOpgehaaldeLeden as $lid): ?>
                                <tr class="<?php echo ($lid['nummer'] % 10 == 0) ? 'bg-gray-100' : ''; ?>">
                                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo $lid['nummer']; ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo $lid['product']; ?></td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo $lid['hoeveelheid']; ?></td>
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
