<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';

// Functie om te controleren of een certificaat bestaat
function certificaatBestaat($db, $certificaat) {
    $stmt = $db->prepare("SELECT certificaat FROM leden WHERE certificaat = :certificaat");
    $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    return $row !== false;
}

// Functie om alle certificaten op te halen
function getAlleCertificaten($db) {
    $result = $db->query("SELECT l.leden_id, l.certificaat FROM leden l GROUP BY l.leden_id ORDER BY l.certificaat");
    $certificaten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $certificaten[] = $row;
    }
    return $certificaten;
}

// Functie om de gebruikersnaam op te halen
function getGebruikersnaam() {
    $username = '';
    if (isset($_SERVER['HTTP_AUTHORIZATION']) || isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        $authorization_header = '';
        if (isset($_SERVER['HTTP_AUTHORIZATION']) && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorization_header = $_SERVER['HTTP_AUTHORIZATION'];
        }
        elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) && !empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $authorization_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }
        if (!empty($authorization_header)) {
            list($username_temp, $userpass_temp) = explode(':', base64_decode(substr($authorization_header, 6)));
            $username = $username_temp;
        }
    }
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
    return !empty($username) ? $username : 'Anoniem';
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

// Functie om de laatste registratie van de huidige gebruiker op te halen
function getLaatsteRegistratie($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $stmt = $db->prepare("
        SELECT r.id, r.leden_id, r.gebruiker, r.registratie_tijd, u.uitgiftedatum,
               l.certificaat, l.naam as lid_naam, p.naam as product, l.monden
        FROM registraties r
        JOIN uitgiftedatum u ON r.uitgiftedag = u.id
        JOIN leden l ON r.leden_id = l.leden_id
        JOIN producten p ON l.product_id = p.product_id
        WHERE r.uitgiftedag = :uitgiftedag_id
        AND r.gebruiker = :gebruiker
        ORDER BY r.registratie_tijd DESC
        LIMIT 1
    ");

    $stmt->bindValue(':uitgiftedag_id', $uitgiftedag['id'], SQLITE3_INTEGER);
    $stmt->bindValue(':gebruiker', getGebruikersnaam(), SQLITE3_TEXT);

    $result = $stmt->execute();
    return $result->fetchArray(SQLITE3_ASSOC);
}

// Functie om alle leden op te halen
function getLeden($db) {
    $result = $db->query("
        SELECT l.leden_id, l.certificaat, l.product_id, l.monden, l.naam, p.naam as product_naam
        FROM leden l
        JOIN producten p ON l.product_id = p.product_id
        ORDER BY l.certificaat
    ");
    $leden = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $leden[] = $row;
    }
    return $leden;
}

// Functie om het aantal leden te tellen
function getLedenCount($db) {
    $result = $db->query("SELECT COUNT(*) as count FROM leden");
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row['count'];
}

// Functie om het aantal niet-opgehaalde producten per product te berekenen
function getNietOpgehaaldeProductenPerProduct($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);
    $nietOpgehaaldeProducten = [];

    $productenResult = $db->query("SELECT product_id, naam FROM producten");
    while ($productRow = $productenResult->fetchArray(SQLITE3_ASSOC)) {
        $productId = $productRow['product_id'];
        $productNaam = $productRow['naam'];

        $result = $db->query("
            SELECT SUM(leden.monden) as totalHoeveelheid
            FROM leden
            JOIN producten ON leden.product_id = producten.product_id
            WHERE leden.leden_id NOT IN (
                SELECT leden_id
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

// Functie om certificaten die nog niet hebben opgehaald op te halen voor de dropdown
function getNogNietOpgehaaldeCertificaten($db) {
    $uitgiftedag = getHuidigeUitgiftedag($db);

    $result = $db->query("
        SELECT l.leden_id, l.certificaat, p.naam as product, l.monden, l.naam as lid_naam
        FROM leden l
        JOIN producten p ON l.product_id = p.product_id
        WHERE l.leden_id NOT IN (
            SELECT leden_id
            FROM registraties
            WHERE uitgiftedag = {$uitgiftedag['id']}
        )
        ORDER BY l.certificaat
    ");
    $certificaten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $certificaten[] = $row;
    }
    return $certificaten;
}

// Functie om op te halen welke certificaten zijn opgehaald op geselecteerde datums
function getOpgehaaldeCertificatenPerDatum($db, $uitgiftedatumIds) {
    if (empty($uitgiftedatumIds)) {
        return [];
    }

    $placeholders = implode(',', array_fill(0, count($uitgiftedatumIds), '?'));
    $query = "SELECT leden_id, uitgiftedag FROM registraties WHERE uitgiftedag IN ($placeholders)";

    $stmt = $db->prepare($query);
    foreach ($uitgiftedatumIds as $i => $id) {
        $stmt->bindValue($i+1, $id, SQLITE3_INTEGER);
    }

    $result = $stmt->execute();
    $opgehaaldeData = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $opgehaaldeData[$row['uitgiftedag']][] = $row['leden_id'];
    }

    // Zorg dat elke datum een entry heeft
    foreach ($uitgiftedatumIds as $datumId) {
        if (!isset($opgehaaldeData[$datumId])) {
            $opgehaaldeData[$datumId] = [];
        }
    }

    return $opgehaaldeData;
}

// Functie om alle producten op te halen
function getProducten($db) {
    $result = $db->query("SELECT product_id, naam FROM producten ORDER BY naam");
    $producten = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $producten[] = $row;
    }
    return $producten;
}

// Functie om het aantal producten te tellen
function getProductenCount($db) {
    $result = $db->query("SELECT COUNT(*) as count FROM producten");
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row['count'];
}

// Functie om productinformatie per certificaat op te halen
function getProductInfoPerCertificaat($db) {
    $result = $db->query("
        SELECT l.leden_id, l.certificaat,
               GROUP_CONCAT(p.naam || ' (' || l.monden || ')', ', ') as producten,
               l.naam as lid_naam
        FROM leden l
        JOIN producten p ON l.product_id = p.product_id
        GROUP BY l.leden_id
    ");
    $productInfo = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $productInfo[$row['leden_id']] = [
            'certificaat' => $row['certificaat'],
            'producten' => $row['producten'],
            'naam' => $row['lid_naam']
        ];
    }
    return $productInfo;
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
        $productId = $product['product_id'];
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
            AND leden_id NOT IN (
                SELECT leden_id FROM registraties WHERE uitgiftedag = {$uitgiftedag['id']}
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
            AND leden_id NOT IN (
                SELECT leden_id FROM registraties WHERE uitgiftedag = {$uitgiftedag['id']}
            )
        ");
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $nietOpgehaaldMonden = $row['totalHoeveelheid'] ?? 0;
        $totaalNietOpgehaaldMonden += $nietOpgehaaldMonden;

        // Totaal aantal monden dat al is opgehaald
        $result = $db->query("
            SELECT SUM(leden.monden) as totalHoeveelheid
            FROM registraties
            JOIN leden ON registraties.leden_id = leden.leden_id
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

// Functie om rapportgegevens op te halen voor een specifieke datum
function getRapportGegevens($db, $uitgiftedatumId) {
    // Haal basisinformatie over de uitgiftedatum
    $result = $db->query("SELECT uitgiftedatum, starttijd, eindtijd FROM uitgiftedatum WHERE id = $uitgiftedatumId");
    $uitgiftedatumInfo = $result->fetchArray(SQLITE3_ASSOC);

    // Haal alle registraties voor deze datum
    $result = $db->query("
        SELECT r.leden_id, r.gebruiker, r.registratie_tijd, l.product_id, p.naam as product, l.monden, l.naam as lid_naam, l.certificaat
        FROM registraties r
        JOIN leden l ON r.leden_id = l.leden_id
        JOIN producten p ON l.product_id = p.product_id
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
        JOIN leden l ON r.leden_id = l.leden_id
        WHERE r.uitgiftedag = $uitgiftedatumId
    ");
    $stats = $result->fetchArray(SQLITE3_ASSOC);
    $totalMonden = $stats['totalMonden'] ?? 0;

    // Haal certificaten die niet zijn opgehaald voor deze datum
    $result = $db->query("
        SELECT l.leden_id, l.certificaat, p.naam as product, l.monden, l.naam as lid_naam
        FROM leden l
        JOIN producten p ON l.product_id = p.product_id
        WHERE l.leden_id NOT IN (
            SELECT leden_id FROM registraties WHERE uitgiftedag = $uitgiftedatumId
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

// Functie om registraties op te halen met filters
function getRegistraties($db, $filters = []) {
    $where = [];
    $params = [];

    if (!empty($filters['datum_id'])) {
        $where[] = "r.uitgiftedag = :datum_id";
        $params[':datum_id'] = $filters['datum_id'];
    }

    if (!empty($filters['leden_id'])) {
        $where[] = "r.leden_id = :leden_id";
        $params[':leden_id'] = $filters['leden_id'];
    }

    $whereClause = !empty($where) ? "WHERE " . implode(" AND ", $where) : "";

    $query = "
        SELECT r.id, r.leden_id, r.gebruiker, r.registratie_tijd, u.uitgiftedatum,
               l.certificaat, l.naam as lid_naam, p.naam as product_naam
        FROM registraties r
        JOIN uitgiftedatum u ON r.uitgiftedag = u.id
        JOIN leden l ON r.leden_id = l.leden_id
        JOIN producten p ON l.product_id = p.product_id
        $whereClause
        ORDER BY r.registratie_tijd DESC
    ";

    $stmt = $db->prepare($query);

    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value, SQLITE3_INTEGER);
    }

    $result = $stmt->execute();
    $registraties = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $registraties[] = $row;
    }
    return $registraties;
}

// Functie om het aantal registraties te tellen
function getRegistratiesCount($db) {
    $result = $db->query("SELECT COUNT(*) as count FROM registraties");
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row['count'];
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

    $productenResult = $db->query("SELECT product_id, naam FROM producten");
    while ($productRow = $productenResult->fetchArray(SQLITE3_ASSOC)) {
        $productId = $productRow['product_id'];
        $productNaam = $productRow['naam'];

        $countResult = $db->query("
            SELECT COUNT(*) as count, SUM(l.monden) as totalHoeveelheid
            FROM registraties r
            JOIN leden l ON r.leden_id = l.leden_id
            WHERE l.product_id = $productId AND r.uitgiftedag = {$uitgiftedag['id']}
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

// Functie om het totaal aantal niet-opgehaalde producten te berekenen
function getTotaalNietOpgehaaldeProducten($db) {
    $nogNietOpgehaaldeCertificaten = getNogNietOpgehaaldeCertificaten($db);
    $totaal = 0;
    foreach ($nogNietOpgehaaldeCertificaten as $certificaat) {
        $totaal += $certificaat['monden'];
    }
    return $totaal;
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
                  WHERE leden_id = ? AND uitgiftedag IN ($datumPlaceholders)";

        $stmt = $db->prepare($query);
        $stmt->bindValue(1, $certificaat['leden_id'], SQLITE3_INTEGER);

        // Bind alle datum IDs
        foreach ($uitgiftedatumIds as $i => $id) {
            $stmt->bindValue($i+2, $id, SQLITE3_INTEGER);
        }

        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        $totaalPerCertificaat[$certificaat['leden_id']] = $row['totaal'];
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

// Functie om alle uitgiftedagen op te halen
function getUitgiftedagen($db) {
    $result = $db->query("
        SELECT id, uitgiftedatum, starttijd, eindtijd
        FROM uitgiftedatum
        ORDER BY uitgiftedatum DESC
    ");
    $uitgiftedagen = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $uitgiftedagen[] = $row;
    }
    return $uitgiftedagen;
}

// Functie om het aantal uitgiftedagen te tellen
function getUitgiftedagenCount($db) {
    $result = $db->query("SELECT COUNT(*) as count FROM uitgiftedatum");
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row['count'];
}

// Functie om alle uitgiftedata op te halen
function getUitgiftedata($db) {
    $result = $db->query("SELECT id, uitgiftedatum FROM uitgiftedatum ORDER BY uitgiftedatum DESC");
    $data = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $data[] = $row;
    }
    return $data;
}

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

// Functie om de status van de volgende uitgiftedag te bepalen
function getUitgifteStatus($volgendeUitgiftedag) {
    if (!$volgendeUitgiftedag) {
        return [
            'status' => 'geen',
            'message' => 'Geen geplande uitgiftes gevonden'
        ];
    }

    $nu = new DateTime();
    $uitgiftedatum = new DateTime($volgendeUitgiftedag['uitgiftedatum'] . ' ' . $volgendeUitgiftedag['starttijd']);
    $eindtijd = new DateTime($volgendeUitgiftedag['uitgiftedatum'] . ' ' . $volgendeUitgiftedag['eindtijd']);

    $isVandaag = ($volgendeUitgiftedag['uitgiftedatum'] === $nu->format('Y-m-d'));

    if ($isVandaag) {
        if ($nu < $uitgiftedatum) {
            // Nog niet begonnen
            $verschil = $nu->diff($uitgiftedatum);
            $uren = $verschil->h + ($verschil->days * 24);
            $minuten = $verschil->i;

            if ($verschil->days > 0) {
                $message = "Begint over " . $verschil->days . " dagen om " . substr($volgendeUitgiftedag['starttijd'], 0, 5);
            } elseif ($uren > 0) {
                $message = "Begint over " . $uren . " uur en " . $minuten . " minuten";
            } else {
                $message = "Begint over " . $minuten . " minuten";
            }

            return [
                'status' => 'toekomstig',
                'message' => $message,
                'isVandaag' => true,
                'isOpen' => false
            ];
        } elseif ($nu >= $uitgiftedatum && $nu <= $eindtijd) {
            // Nu open
            $eindeOver = $nu->diff($eindtijd);
            $uren = $eindeOver->h + ($eindeOver->days * 24);
            $minuten = $eindeOver->i;

            if ($eindeOver->days > 0) {
                $message = "Nu open, sluit over " . $eindeOver->days . " dagen om " . substr($volgendeUitgiftedag['eindtijd'], 0, 5);
            } elseif ($uren > 0) {
                $message = "Nu open, sluit over " . $uren . " uur en " . $minuten . " minuten";
            } else {
                $message = "Nu open, sluit over " . $minuten . " minuten";
            }

            return [
                'status' => 'open',
                'message' => $message,
                'isVandaag' => true,
                'isOpen' => true
            ];
        } else {
            // Vandaag al afgelopen
            return [
                'status' => 'afgelopen',
                'message' => "Afgelopen om " . substr($volgendeUitgiftedag['eindtijd'], 0, 5),
                'isVandaag' => true,
                'isOpen' => false
            ];
        }
    } else {
        // Toekomstige datum
        $verschil = $nu->diff(new DateTime($volgendeUitgiftedag['uitgiftedatum']));

        if ($verschil->days == 1) {
            $message = "Morgen om " . substr($volgendeUitgiftedag['starttijd'], 0, 5);
        } elseif ($verschil->days < 7) {
            $message = "Over " . $verschil->days . " dagen";
        } else {
            $message = "Op " . date('d-m-Y', strtotime($volgendeUitgiftedag['uitgiftedatum']));
        }

        return [
            'status' => 'toekomstig',
            'message' => $message,
            'isVandaag' => false,
            'isOpen' => false
        ];
    }
}

// Functie om de eerstvolgende uitgiftedag te vinden
function getVolgendeUitgiftedag($db) {
    $nu = new DateTime();
    $vandaag = $nu->format('Y-m-d');
    $huidigeTijd = $nu->format('H:i:s');

    // Zoek eerst vandaag nog openstaande of toekomstige uitgiftedagen
    $stmt = $db->prepare("
        SELECT id, uitgiftedatum, starttijd, eindtijd
        FROM uitgiftedatum
        WHERE (uitgiftedatum = :vandaag AND eindtijd > :huidigeTijd)
           OR (uitgiftedatum > :vandaag)
        ORDER BY uitgiftedatum ASC, starttijd ASC
        LIMIT 1
    ");
    $stmt->bindValue(':vandaag', $vandaag, SQLITE3_TEXT);
    $stmt->bindValue(':huidigeTijd', $huidigeTijd, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    return $row;
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

// Functie om een audit log te schrijven
function logAction($actionType, $details) {
    global $logFile;
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $gebruikersnaam = getGebruikersnaam();
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$gebruikersnaam] [$ipAddress] - [$actionType]   Details: $details\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

// Functie om registratie toe te voegen
function registreerCertificaat($db, $certificaat) {
    // Controleer of het certificaat bestaat
    if (!certificaatBestaat($db, $certificaat)) {
        logAction('REGISTRATIE_FOUT', "Certificaat $certificaat bestaat niet");
        return "certificaat_bestaat_niet";
    }

    // Haal het leden_id op basis van certificaat
    $stmt = $db->prepare("SELECT leden_id FROM leden WHERE certificaat = :certificaat");
    $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) {
        logAction('REGISTRATIE_FOUT', "Geen leden_id gevonden voor certificaat $certificaat");
        return false;
    }

    $ledenId = $row['leden_id'];
    $registratieTijd = date('Y-m-d H:i:s');
    $uitgiftedag = getHuidigeUitgiftedag($db);
    $gebruiker = getGebruikersnaam();

    // Controleer of dit certificaat vandaag al geregistreerd is
    $stmt = $db->prepare("
        SELECT leden_id
        FROM registraties
        WHERE leden_id = :leden_id AND uitgiftedag = :uitgiftedag
    ");
    $stmt->bindValue(':leden_id', $ledenId, SQLITE3_INTEGER);
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        logAction('REGISTRATIE_DUBBEL', "Certificaat $certificaat is vandaag al geregistreerd");
        return false;
    }

    // Voeg de registratie toe
    $stmt = $db->prepare("
        INSERT INTO registraties (leden_id, gebruiker, registratie_tijd, uitgiftedag)
        VALUES (:leden_id, :gebruiker, :registratie_tijd, :uitgiftedag)
    ");
    $stmt->bindValue(':leden_id', $ledenId, SQLITE3_INTEGER);
    $stmt->bindValue(':gebruiker', $gebruiker, SQLITE3_TEXT);
    $stmt->bindValue(':registratie_tijd', $registratieTijd, SQLITE3_TEXT);
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);

    try {
        $stmt->execute();
        logAction('REGISTRATIE_TOEGEVOEGD', "Certificaat $certificaat (leden_id: $ledenId) geregistreerd door $gebruiker op " . $uitgiftedag['uitgiftedatum']);
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
        SELECT id, leden_id, gebruiker FROM registraties
        WHERE id = (
            SELECT id FROM registraties
            WHERE uitgiftedag = :uitgiftedag AND gebruiker = :gebruiker
            ORDER BY registratie_tijd DESC LIMIT 1
        )
    ");
    $stmt->bindValue(':uitgiftedag', $uitgiftedag['id'], SQLITE3_INTEGER);
    $stmt->bindValue(':gebruiker', getGebruikersnaam(), SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        $laatsteId = $row['id'];
        $laatsteLedenId = $row['leden_id'];
        $laatsteGebruiker = $row['gebruiker'];

        // Haal het certificaatnummer op voor logging
        $stmtCert = $db->prepare("SELECT certificaat FROM leden WHERE leden_id = :leden_id");
        $stmtCert->bindValue(':leden_id', $laatsteLedenId, SQLITE3_INTEGER);
        $resultCert = $stmtCert->execute();
        $rowCert = $resultCert->fetchArray(SQLITE3_ASSOC);
        $laatsteCertificaat = $rowCert['certificaat'] ?? 'onbekend';

        $stmt = $db->prepare("
            DELETE FROM registraties
            WHERE id = :id
        ");
        $stmt->bindValue(':id', $laatsteId, SQLITE3_INTEGER);

        try {
            $stmt->execute();
            logAction('REGISTRATIE_VERWIJDERD', "Registratie van certificaat $laatsteCertificaat (leden_id: $laatsteLedenId) door $laatsteGebruiker verwijderd");
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

// Functie om een lid te verwijderen
function verwijderLid($db, $leden_id) {
    try {
        // Controleer of het lid bestaat
        $stmt = $db->prepare("SELECT certificaat FROM leden WHERE leden_id = :leden_id");
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if (!$row) {
            return ['success' => false, 'message' => "Lid met ID $leden_id niet gevonden."];
        }

        $certificaat = $row['certificaat'];

        // Controleer of het lid al registraties heeft
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM registraties WHERE leden_id = :leden_id");
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row['count'] > 0) {
            return ['success' => false, 'message' => "Lid met certificaat $certificaat kan niet worden verwijderd omdat het al registraties heeft."];
        }

        // Verwijder het lid
        $stmt = $db->prepare("DELETE FROM leden WHERE leden_id = :leden_id");
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $stmt->execute();

        logAction('LID_VERWIJDERD', "Lid verwijderd: ID $leden_id, certificaat $certificaat");

        return ['success' => true, 'message' => "Lid succesvol verwijderd."];
    } catch (Exception $e) {
        logAction('LID_VERWIJDER_FOUT', "Fout bij verwijderen lid: ID $leden_id, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij verwijderen lid: " . $e->getMessage()];
    }
}

// Functie om een registratie te verwijderen
function verwijderRegistratie($db, $registratie_id) {
    try {
        // Controleer of de registratie bestaat
        $stmt = $db->prepare("
            SELECT r.id, r.leden_id, r.gebruiker, r.registratie_tijd, u.uitgiftedatum, l.certificaat
            FROM registraties r
            JOIN uitgiftedatum u ON r.uitgiftedag = u.id
            JOIN leden l ON r.leden_id = l.leden_id
            WHERE r.id = :registratie_id
        ");
        $stmt->bindValue(':registratie_id', $registratie_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if (!$row) {
            return ['success' => false, 'message' => "Registratie met ID $registratie_id niet gevonden."];
        }

        $certificaat = $row['certificaat'];
        $gebruiker = $row['gebruiker'];
        $uitgiftedatum = $row['uitgiftedatum'];

        // Verwijder de registratie
        $stmt = $db->prepare("DELETE FROM registraties WHERE id = :registratie_id");
        $stmt->bindValue(':registratie_id', $registratie_id, SQLITE3_INTEGER);
        $stmt->execute();

        logAction('REGISTRATIE_VERWIJDERD', "Registratie verwijderd: ID $registratie_id, certificaat $certificaat, gebruiker $gebruiker, datum $uitgiftedatum");

        return ['success' => true, 'message' => "Registratie succesvol verwijderd."];
    } catch (Exception $e) {
        logAction('REGISTRATIE_VERWIJDER_FOUT', "Fout bij verwijderen registratie: ID $registratie_id, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij verwijderen registratie: " . $e->getMessage()];
    }
}

// Functie om een lid toe te voegen
function voegLidToe($db, $certificaat, $product_id, $monden, $naam) {
    try {
        // Controleer of certificaat al bestaat
        $stmt = $db->prepare("SELECT leden_id FROM leden WHERE certificaat = :certificaat");
        $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row) {
            return ['success' => false, 'message' => "Certificaat $certificaat bestaat al."];
        }

        // Voeg het nieuwe lid toe
        $stmt = $db->prepare("
            INSERT INTO leden (certificaat, product_id, monden, naam)
            VALUES (:certificaat, :product_id, :monden, :naam)
        ");
        $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
        $stmt->bindValue(':product_id', $product_id, SQLITE3_INTEGER);
        $stmt->bindValue(':monden', $monden, SQLITE3_INTEGER);
        $stmt->bindValue(':naam', $naam, SQLITE3_TEXT);

        $stmt->execute();

        $ledenId = $db->lastInsertRowID();
        logAction('LID_TOEGEVOEGD', "Lid toegevoegd: certificaat $certificaat, product_id $product_id, monden $monden, naam $naam (ID: $ledenId)");

        return ['success' => true, 'message' => "Lid succesvol toegevoegd.", 'leden_id' => $ledenId];
    } catch (Exception $e) {
        logAction('LID_TOEVOEG_FOUT', "Fout bij toevoegen lid: certificaat $certificaat, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij toevoegen lid: " . $e->getMessage()];
    }
}

// Functie om een registratie toe te voegen
function voegRegistratieToe($db, $leden_id, $gebruiker, $registratie_tijd, $uitgiftedag) {
    try {
        // Controleer of deze combinatie al bestaat
        $stmt = $db->prepare("
            SELECT id FROM registraties
            WHERE leden_id = :leden_id AND uitgiftedag = :uitgiftedag
        ");
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $stmt->bindValue(':uitgiftedag', $uitgiftedag, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row) {
            return ['success' => false, 'message' => "Deze registratie bestaat al voor dit lid op deze datum."];
        }

        // Voeg de nieuwe registratie toe
        $stmt = $db->prepare("
            INSERT INTO registraties (leden_id, gebruiker, registratie_tijd, uitgiftedag)
            VALUES (:leden_id, :gebruiker, :registratie_tijd, :uitgiftedag)
        ");
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $stmt->bindValue(':gebruiker', $gebruiker, SQLITE3_TEXT);
        $stmt->bindValue(':registratie_tijd', $registratie_tijd, SQLITE3_TEXT);
        $stmt->bindValue(':uitgiftedag', $uitgiftedag, SQLITE3_INTEGER);

        $stmt->execute();

        $registratieId = $db->lastInsertRowID();

        // Haal het certificaatnummer op voor logging
        $stmtCert = $db->prepare("SELECT certificaat FROM leden WHERE leden_id = :leden_id");
        $stmtCert->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $resultCert = $stmtCert->execute();
        $rowCert = $resultCert->fetchArray(SQLITE3_ASSOC);
        $certificaat = $rowCert['certificaat'] ?? 'onbekend';

        logAction('REGISTRATIE_TOEGEVOEGD', "Registratie toegevoegd: ID $registratieId, leden_id $leden_id, certificaat $certificaat, gebruiker $gebruiker, datum $uitgiftedag");

        return ['success' => true, 'message' => "Registratie succesvol toegevoegd.", 'registratie_id' => $registratieId];
    } catch (Exception $e) {
        logAction('REGISTRATIE_TOEVOEG_FOUT', "Fout bij toevoegen registratie: leden_id $leden_id, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij toevoegen registratie: " . $e->getMessage()];
    }
}

// Functie om een uitgiftedag toe te voegen
function voegUitgiftedagToe($db, $uitgiftedatum, $starttijd, $eindtijd) {
    try {
        // Controleer of de datum al bestaat
        $stmt = $db->prepare("SELECT id FROM uitgiftedatum WHERE uitgiftedatum = :uitgiftedatum");
        $stmt->bindValue(':uitgiftedatum', $uitgiftedatum, SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row) {
            return ['success' => false, 'message' => "Deze uitgiftedatum bestaat al."];
        }

        // Controleer of eindtijd na starttijd is
        if (strtotime($eindtijd) <= strtotime($starttijd)) {
            return ['success' => false, 'message' => "Eindtijd moet na starttijd zijn."];
        }

        // Voeg de nieuwe uitgiftedag toe
        $stmt = $db->prepare("
            INSERT INTO uitgiftedatum (uitgiftedatum, starttijd, eindtijd)
            VALUES (:uitgiftedatum, :starttijd, :eindtijd)
        ");
        $stmt->bindValue(':uitgiftedatum', $uitgiftedatum, SQLITE3_TEXT);
        $stmt->bindValue(':starttijd', $starttijd, SQLITE3_TEXT);
        $stmt->bindValue(':eindtijd', $eindtijd, SQLITE3_TEXT);

        $stmt->execute();

        $uitgiftedagId = $db->lastInsertRowID();
        logAction('UITGIFTEDAG_TOEGEVOEGD', "Uitgiftedag toegevoegd: ID $uitgiftedagId, datum $uitgiftedatum, $starttijd - $eindtijd");

        return ['success' => true, 'message' => "Uitgiftedag succesvol toegevoegd.", 'uitgiftedag_id' => $uitgiftedagId];
    } catch (Exception $e) {
        logAction('UITGIFTEDAG_TOEVOEG_FOUT', "Fout bij toevoegen uitgiftedag: $uitgiftedatum, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij toevoegen uitgiftedag: " . $e->getMessage()];
    }
}

// Functie om een lid te wijzigen
function wijzigLid($db, $leden_id, $certificaat, $product_id, $monden, $naam) {
    try {
        // Controleer of certificaat al bestaat voor een ander lid
        $stmt = $db->prepare("
            SELECT leden_id FROM leden
            WHERE certificaat = :certificaat AND leden_id != :leden_id
        ");
        $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row) {
            return ['success' => false, 'message' => "Certificaat $certificaat is al in gebruik door een ander lid."];
        }

        // Wijzig het lid
        $stmt = $db->prepare("
            UPDATE leden
            SET certificaat = :certificaat,
                product_id = :product_id,
                monden = :monden,
                naam = :naam
            WHERE leden_id = :leden_id
        ");
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $stmt->bindValue(':certificaat', $certificaat, SQLITE3_INTEGER);
        $stmt->bindValue(':product_id', $product_id, SQLITE3_INTEGER);
        $stmt->bindValue(':monden', $monden, SQLITE3_INTEGER);
        $stmt->bindValue(':naam', $naam, SQLITE3_TEXT);

        $stmt->execute();

        logAction('LID_GEWIJZIGD', "Lid gewijzigd: ID $leden_id, certificaat $certificaat, product_id $product_id, monden $monden, naam $naam");

        return ['success' => true, 'message' => "Lid succesvol gewijzigd."];
    } catch (Exception $e) {
        logAction('LID_WIJZIG_FOUT', "Fout bij wijzigen lid: ID $leden_id, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij wijzigen lid: " . $e->getMessage()];
    }
}

// Functie om een registratie te wijzigen
function wijzigRegistratie($db, $registratie_id, $leden_id, $gebruiker, $registratie_tijd, $uitgiftedag) {
    try {
        // Controleer of deze combinatie al bestaat voor een andere registratie
        $stmt = $db->prepare("
            SELECT id FROM registraties
            WHERE leden_id = :leden_id AND uitgiftedag = :uitgiftedag AND id != :registratie_id
        ");
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $stmt->bindValue(':uitgiftedag', $uitgiftedag, SQLITE3_INTEGER);
        $stmt->bindValue(':registratie_id', $registratie_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row) {
            return ['success' => false, 'message' => "Deze registratie bestaat al voor dit lid op deze datum."];
        }

        // Wijzig de registratie
        $stmt = $db->prepare("
            UPDATE registraties
            SET leden_id = :leden_id,
                gebruiker = :gebruiker,
                registratie_tijd = :registratie_tijd,
                uitgiftedag = :uitgiftedag
            WHERE id = :registratie_id
        ");
        $stmt->bindValue(':registratie_id', $registratie_id, SQLITE3_INTEGER);
        $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $stmt->bindValue(':gebruiker', $gebruiker, SQLITE3_TEXT);
        $stmt->bindValue(':registratie_tijd', $registratie_tijd, SQLITE3_TEXT);
        $stmt->bindValue(':uitgiftedag', $uitgiftedag, SQLITE3_INTEGER);

        $stmt->execute();

        // Haal het certificaatnummer op voor logging
        $stmtCert = $db->prepare("SELECT certificaat FROM leden WHERE leden_id = :leden_id");
        $stmtCert->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
        $resultCert = $stmtCert->execute();
        $rowCert = $resultCert->fetchArray(SQLITE3_ASSOC);
        $certificaat = $rowCert['certificaat'] ?? 'onbekend';

        logAction('REGISTRATIE_GEWIJZIGD', "Registratie gewijzigd: ID $registratie_id, leden_id $leden_id, certificaat $certificaat, gebruiker $gebruiker, datum $uitgiftedag");

        return ['success' => true, 'message' => "Registratie succesvol gewijzigd."];
    } catch (Exception $e) {
        logAction('REGISTRATIE_WIJZIG_FOUT', "Fout bij wijzigen registratie: ID $registratie_id, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij wijzigen registratie: " . $e->getMessage()];
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

// Functie om een uitgiftedag te wijzigen
function wijzigUitgiftedag($db, $id, $uitgiftedatum, $starttijd, $eindtijd) {
    try {
        // Controleer of de datum al bestaat voor een andere uitgiftedag
        $stmt = $db->prepare("
            SELECT id FROM uitgiftedatum
            WHERE uitgiftedatum = :uitgiftedatum AND id != :id
        ");
        $stmt->bindValue(':uitgiftedatum', $uitgiftedatum, SQLITE3_TEXT);
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        if ($row) {
            return ['success' => false, 'message' => "Deze uitgiftedatum bestaat al voor een andere dag."];
        }

        // Controleer of eindtijd na starttijd is
        if (strtotime($eindtijd) <= strtotime($starttijd)) {
            return ['success' => false, 'message' => "Eindtijd moet na starttijd zijn."];
        }

        // Wijzig de uitgiftedag
        $stmt = $db->prepare("
            UPDATE uitgiftedatum
            SET uitgiftedatum = :uitgiftedatum,
                starttijd = :starttijd,
                eindtijd = :eindtijd
            WHERE id = :id
        ");
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->bindValue(':uitgiftedatum', $uitgiftedatum, SQLITE3_TEXT);
        $stmt->bindValue(':starttijd', $starttijd, SQLITE3_TEXT);
        $stmt->bindValue(':eindtijd', $eindtijd, SQLITE3_TEXT);

        $stmt->execute();

        logAction('UITGIFTEDAG_GEWIJZIGD', "Uitgiftedag gewijzigd: ID $id, datum $uitgiftedatum, $starttijd - $eindtijd");

        return ['success' => true, 'message' => "Uitgiftedag succesvol gewijzigd."];
    } catch (Exception $e) {
        logAction('UITGIFTEDAG_WIJZIG_FOUT', "Fout bij wijzigen uitgiftedag: ID $id, Error: " . $e->getMessage());
        return ['success' => false, 'message' => "Fout bij wijzigen uitgiftedag: " . $e->getMessage()];
    }
}


?>
