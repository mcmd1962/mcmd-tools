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
}

// Haal certificaten die nog niet hebben opgehaald op voor de dropdown
$nogNietOpgehaaldeCertificatenVoorDropdown = [];
if ($uitgifteOpen) {
    $nogNietOpgehaaldeCertificatenVoorDropdown = getNogNietOpgehaaldeCertificaten($db);
}

?>

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
