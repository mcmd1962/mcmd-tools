<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';
require_once 'product-functions.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Haal alle uitgiftedata en leden op
$uitgiftedata = getUitgiftedata($db);
$leden = getLeden($db);

// Standaard filters
$filters = [
    'datum_id' => isset($_GET['datum_id']) ? $_GET['datum_id'] : null,
    'leden_id' => isset($_GET['leden_id']) ? $_GET['leden_id'] : null
];

// Haal registraties op met filters
$registraties = getRegistraties($db, $filters);

// Verwerk formuliereacties
$message = '';
$messageType = ''; // success, error, info

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        $action = $_POST['action'];

        if ($action === 'toevoegen') {
            $leden_id = $_POST['leden_id'];
            $gebruiker = getGebruikersnaam();
            $registratie_tijd = date('Y-m-d H:i:s');
            $uitgiftedag = $_POST['uitgiftedag'];

            $result = voegRegistratieToe($db, $leden_id, $gebruiker, $registratie_tijd, $uitgiftedag);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de registraties
                $registraties = getRegistraties($db, $filters);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
        elseif ($action === 'wijzigen') {
            $registratie_id = $_POST['registratie_id'];
            $leden_id = $_POST['leden_id'];
            $gebruiker = $_POST['gebruiker'];
            $registratie_tijd = $_POST['registratie_tijd'];
            $uitgiftedag = $_POST['uitgiftedag'];

            $result = wijzigRegistratie($db, $registratie_id, $leden_id, $gebruiker, $registratie_tijd, $uitgiftedag);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de registraties
                $registraties = getRegistraties($db, $filters);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
        elseif ($action === 'verwijderen') {
            $registratie_id = $_POST['registratie_id'];

            $result = verwijderRegistratie($db, $registratie_id);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de registraties
                $registraties = getRegistraties($db, $filters);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
    }
}

// Haal de registratie voor bewerken als er een edit_id is
$editRegistratie = null;
if (isset($_GET['edit']) && is_numeric($_GET['edit'])) {
    $registratie_id = $_GET['edit'];
    $stmt = $db->prepare("
        SELECT r.id, r.leden_id, r.gebruiker, r.registratie_tijd, r.uitgiftedag,
               l.certificaat, l.naam as lid_naam, p.naam as product_naam, u.uitgiftedatum
        FROM registraties r
        JOIN leden l ON r.leden_id = l.leden_id
        JOIN producten p ON l.product_id = p.product_id
        JOIN uitgiftedatum u ON r.uitgiftedag = u.id
        WHERE r.id = :registratie_id
    ");
    $stmt->bindValue(':registratie_id', $registratie_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $editRegistratie = $result->fetchArray(SQLITE3_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registraties Beheer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .message {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
        }
        .message.success {
            color: #3c763d;
            background-color: #dff0d8;
            border-color: #d6e9c6;
        }
        .message.error {
            color: #a94442;
            background-color: #f2dede;
            border-color: #ebccd1;
        }
        .message.info {
            color: #31708f;
            background-color: #d9edf7;
            border-color: #bce8f1;
        }
    </style>
</head>
<body class="bg-gray-100 font-sans leading-normal tracking-normal">
    <div class="container w-full mx-auto pt-10 pb-10">
        <div class="w-full px-4 text-xl text-gray-800 leading-normal">
            <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
                <h1 class="text-2xl font-bold mb-6">Registraties Beheer</h1>

                <!-- Berichten weergave -->
                <?php if (!empty($message)): ?>
                    <div class="message <?php echo $messageType; ?>">
                        <?php echo $message; ?>
                    </div>
                <?php endif; ?>

                <!-- Filter formulier -->
                <div class="mb-8 p-4 border rounded-lg bg-gray-50">
                    <h2 class="text-xl font-bold mb-4">Filter Registraties</h2>
                    <form method="GET" action="" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div>
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="datum_id">
                                Datum
                            </label>
                            <select id="datum_id" name="datum_id" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
                                <option value="">Alle datums</option>
                                <?php foreach ($uitgiftedata as $datum): ?>
                                    <option value="<?php echo $datum['id']; ?>" <?php echo ($filters['datum_id'] == $datum['id']) ? 'selected' : ''; ?>>
                                        <?php echo date('d-m-Y', strtotime($datum['uitgiftedatum'])); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <label class="block text-gray-700 text-sm font-bold mb-2" for="leden_id">
                                Lid
                            </label>
                            <select id="leden_id" name="leden_id" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
                                <option value="">Alle leden</option>
                                <?php foreach ($leden as $lid): ?>
                                    <option value="<?php echo $lid['leden_id']; ?>" <?php echo ($filters['leden_id'] == $lid['leden_id']) ? 'selected' : ''; ?>>
                                        <?php echo $lid['certificaat']; ?> - <?php echo !empty($lid['naam']) ? $lid['naam'] : '[geen naam]'; ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="flex items-end">
                            <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                                Filteren
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Registratie toevoegen/wijzigen formulier -->
                <div class="mb-8 p-4 border rounded-lg bg-gray-50">
                    <h2 class="text-xl font-bold mb-4">
                        <?php echo $editRegistratie ? 'Registratie Wijzigen' : 'Nieuwe Registratie Toevoegen'; ?>
                    </h2>

                    <form method="POST" action="">
                        <input type="hidden" name="action" value="<?php echo $editRegistratie ? 'wijzigen' : 'toevoegen'; ?>">

                        <?php if ($editRegistratie): ?>
                            <input type="hidden" name="registratie_id" value="<?php echo $editRegistratie['id']; ?>">
                        <?php endif; ?>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="leden_id">
                                    Lid
                                </label>
                                <select id="leden_id" name="leden_id" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" required>
                                    <option value="">Selecteer een lid</option>
                                    <?php foreach ($leden as $lid): ?>
                                        <option value="<?php echo $lid['leden_id']; ?>"
                                            <?php echo ($editRegistratie && $editRegistratie['leden_id'] == $lid['leden_id']) ? 'selected' : ''; ?>>
                                            <?php echo $lid['certificaat']; ?> - <?php echo !empty($lid['naam']) ? $lid['naam'] : '[geen naam]'; ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="uitgiftedag">
                                    Datum
                                </label>
                                <select id="uitgiftedag" name="uitgiftedag" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" required>
                                    <option value="">Selecteer een datum</option>
                                    <?php foreach ($uitgiftedata as $datum): ?>
                                        <option value="<?php echo $datum['id']; ?>"
                                            <?php echo ($editRegistratie && $editRegistratie['uitgiftedag'] == $datum['id']) ? 'selected' : ''; ?>>
                                            <?php echo date('d-m-Y', strtotime($datum['uitgiftedatum'])); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>

                        <?php if ($editRegistratie): ?>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                <div>
                                    <label class="block text-gray-700 text-sm font-bold mb-2" for="gebruiker">
                                        Gebruiker
                                    </label>
                                    <input type="text" id="gebruiker" name="gebruiker"
                                           class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                           value="<?php echo $editRegistratie['gebruiker']; ?>" required>
                                </div>

                                <div>
                                    <label class="block text-gray-700 text-sm font-bold mb-2" for="registratie_tijd">
                                        Registratie Tijd
                                    </label>
                                    <input type="datetime-local" id="registratie_tijd" name="registratie_tijd"
                                           class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                           value="<?php echo date('Y-m-d\TH:i', strtotime($editRegistratie['registratie_tijd'])); ?>" required>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="flex items-center justify-between">
                            <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                                <?php echo $editRegistratie ? 'Wijzigen' : 'Toevoegen'; ?>
                            </button>

                            <?php if ($editRegistratie): ?>
                                <a href="muteer-registraties.php<?php echo !empty($filters['datum_id']) ? '?datum_id=' . $filters['datum_id'] : ''; ?><?php echo !empty($filters['leden_id']) ? (empty($filters['datum_id']) ? '?' : '&') . 'leden_id=' . $filters['leden_id'] : ''; ?>"
                                   class="inline-block align-baseline font-bold text-sm text-blue-500 hover:text-blue-800">
                                    Annuleren
                                </a>
                            <?php else: ?>
                                <button type="reset" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                                    Reset
                                </button>
                            <?php endif; ?>
                        </div>
                    </form>
                </div>

                <!-- Registraties overzicht -->
                <div class="mb-6">
                    <h2 class="text-xl font-bold mb-4">Registraties Overzicht</h2>

                    <div class="overflow-x-auto">
                        <table class="min-w-full bg-white border border-gray-300">
                            <thead>
                                <tr class="bg-gray-100">
                                    <th class="py-2 px-4 border">Datum</th>
                                    <th class="py-2 px-4 border">Certificaat</th>
                                    <th class="py-2 px-4 border">Naam</th>
                                    <th class="py-2 px-4 border">Product</th>
                                    <th class="py-2 px-4 border">Tijd</th>
                                    <th class="py-2 px-4 border">Geregistreerd door</th>
                                    <th class="py-2 px-4 border">Acties</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($registraties)): ?>
                                    <tr>
                                        <td colspan="7" class="py-2 px-4 border text-center">Geen registraties gevonden</td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($registraties as $registratie): ?>
                                        <tr class="<?php echo ($registratie['certificaat'] % 2 == 0) ? 'bg-gray-50' : ''; ?>">
                                            <td class="py-2 px-4 border"><?php echo date('d-m-Y', strtotime($registratie['uitgiftedatum'])); ?></td>
                                            <td class="py-2 px-4 border"><?php echo $registratie['certificaat']; ?></td>
                                            <td class="py-2 px-4 border"><?php echo !empty($registratie['lid_naam']) ? $registratie['lid_naam'] : '-'; ?></td>
                                            <td class="py-2 px-4 border"><?php echo $registratie['product_naam']; ?></td>
                                            <td class="py-2 px-4 border"><?php echo date('H:i', strtotime($registratie['registratie_tijd'])); ?></td>
                                            <td class="py-2 px-4 border"><?php echo $registratie['gebruiker']; ?></td>
                                            <td class="py-2 px-4 border">
                                                <a href="?edit=<?php echo $registratie['id']; ?><?php echo !empty($filters['datum_id']) ? '&datum_id=' . $filters['datum_id'] : ''; ?><?php echo !empty($filters['leden_id']) ? '&leden_id=' . $filters['leden_id'] : ''; ?>"
                                                   class="text-blue-500 hover:text-blue-700 mr-2">Wijzigen</a>
                                                <form method="POST" action="" class="inline">
                                                    <input type="hidden" name="action" value="verwijderen">
                                                    <input type="hidden" name="registratie_id" value="<?php echo $registratie['id']; ?>">
                                                    <button type="submit" class="text-red-500 hover:text-red-700"
                                                            onclick="return confirm('Weet je zeker dat je deze registratie wilt verwijderen?')">
                                                        Verwijderen
                                                    </button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
