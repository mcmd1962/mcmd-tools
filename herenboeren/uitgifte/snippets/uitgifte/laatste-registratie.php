<?php
require_once __DIR__ . '/../../product-config.php';
require_once __DIR__ . '/../../product-functions.php';

// Start de sessie en laad configuratie als nog niet gedaan
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Verwerk het registratieformulier
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
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

$laatsteRegistratie = getLaatsteRegistratie($db);
}

// Haal certificaten die nog niet hebben opgehaald op voor de dropdown
$nogNietOpgehaaldeCertificatenVoorDropdown = [];
if ($uitgifteOpen) {
    $nogNietOpgehaaldeCertificatenVoorDropdown = getNogNietOpgehaaldeCertificaten($db);
}

?>

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
                Ongedaan maken
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

