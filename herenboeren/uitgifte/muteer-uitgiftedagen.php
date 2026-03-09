<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';
require_once 'product-functions.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Haal alle uitgiftedagen op
$uitgiftedagen = getUitgiftedagen($db);

// Controleer of de configuratieopties bestaan, zo niet, gebruik standaardwaarden
$defaultStartTijd = isset($defaultStartTijd) ? $defaultStartTijd : '09:00';
$defaultEindTijd = isset($defaultEindTijd) ? $defaultEindTijd : '12:00';

// Verwerk formuliereacties
$message = '';
$messageType = ''; // success, error, info

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        $action = $_POST['action'];

        if ($action === 'toevoegen') {
            $uitgiftedatum = $_POST['uitgiftedatum'];
            $starttijd = $_POST['starttijd'];
            $eindtijd = $_POST['eindtijd'];

            $result = voegUitgiftedagToe($db, $uitgiftedatum, $starttijd, $eindtijd);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de uitgiftedagen
                $uitgiftedagen = getUitgiftedagen($db);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
        elseif ($action === 'wijzigen') {
            $id = $_POST['id'];
            $uitgiftedatum = $_POST['uitgiftedatum'];
            $starttijd = $_POST['starttijd'];
            $eindtijd = $_POST['eindtijd'];

            $result = wijzigUitgiftedag($db, $id, $uitgiftedatum, $starttijd, $eindtijd);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de uitgiftedagen
                $uitgiftedagen = getUitgiftedagen($db);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
    }
}

// Haal de uitgiftedag voor bewerken als er een edit_id is
$editUitgiftedag = null;
if (isset($_GET['edit']) && is_numeric($_GET['edit'])) {
    $id = $_GET['edit'];
    $stmt = $db->prepare("SELECT id, uitgiftedatum, starttijd, eindtijd FROM uitgiftedatum WHERE id = :id");
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $editUitgiftedag = $result->fetchArray(SQLITE3_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Uitgiftedagen Beheer</title>
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
                <h1 class="text-2xl font-bold mb-6">Uitgiftedagen Beheer</h1>

                <!-- Berichten weergave -->
                <?php if (!empty($message)): ?>
                    <div class="message <?php echo $messageType; ?>">
                        <?php echo $message; ?>
                    </div>
                <?php endif; ?>

                <!-- Uitgiftedag toevoegen/wijzigen formulier -->
                <div class="mb-8 p-4 border rounded-lg bg-gray-50">
                    <h2 class="text-xl font-bold mb-4">
                        <?php echo $editUitgiftedag ? 'Uitgiftedag Wijzigen' : 'Nieuwe Uitgiftedag Toevoegen'; ?>
                    </h2>

                    <form method="POST" action="">
                        <input type="hidden" name="action" value="<?php echo $editUitgiftedag ? 'wijzigen' : 'toevoegen'; ?>">

                        <?php if ($editUitgiftedag): ?>
                            <input type="hidden" name="id" value="<?php echo $editUitgiftedag['id']; ?>">
                        <?php endif; ?>

                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="uitgiftedatum">
                                    Datum
                                </label>
                                <input type="date" id="uitgiftedatum" name="uitgiftedatum"
                                       class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                       value="<?php echo $editUitgiftedag ? $editUitgiftedag['uitgiftedatum'] : ''; ?>" required>
                            </div>

                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="starttijd">
                                    Starttijd
                                </label>
                                <input type="time" id="starttijd" name="starttijd"
                                       class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                       value="<?php echo $editUitgiftedag ? substr($editUitgiftedag['starttijd'], 0, 5) : $defaultStartTijd; ?>" required>
                            </div>

                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="eindtijd">
                                    Eindtijd
                                </label>
                                <input type="time" id="eindtijd" name="eindtijd"
                                       class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                       value="<?php echo $editUitgiftedag ? substr($editUitgiftedag['eindtijd'], 0, 5) : $defaultEindTijd; ?>" required>
                            </div>
                        </div>

                        <div class="flex items-center justify-between">
                            <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                                <?php echo $editUitgiftedag ? 'Wijzigen' : 'Toevoegen'; ?>
                            </button>

                            <?php if ($editUitgiftedag): ?>
                                <a href="muteer-uitgiftedagen.php" class="inline-block align-baseline font-bold text-sm text-blue-500 hover:text-blue-800">
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

                <!-- Uitgiftedagen overzicht -->
                <div class="mb-6">
                    <h2 class="text-xl font-bold mb-4">Uitgiftedagen Overzicht</h2>

                    <div class="overflow-x-auto">
                        <table class="min-w-full bg-white border border-gray-300">
                            <thead>
                                <tr class="bg-gray-100">
                                    <th class="py-2 px-4 border">Datum</th>
                                    <th class="py-2 px-4 border">Starttijd</th>
                                    <th class="py-2 px-4 border">Eindtijd</th>
                                    <th class="py-2 px-4 border">Acties</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($uitgiftedagen)): ?>
                                    <tr>
                                        <td colspan="4" class="py-2 px-4 border text-center">Geen uitgiftedagen gevonden</td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($uitgiftedagen as $uitgiftedag): ?>
                                        <tr class="<?php echo (date('d', strtotime($uitgiftedag['uitgiftedatum'])) % 2 == 0) ? 'bg-gray-50' : ''; ?>">
                                            <td class="py-2 px-4 border"><?php echo date('d-m-Y', strtotime($uitgiftedag['uitgiftedatum'])); ?></td>
                                            <td class="py-2 px-4 border"><?php echo substr($uitgiftedag['starttijd'], 0, 5); ?></td>
                                            <td class="py-2 px-4 border"><?php echo substr($uitgiftedag['eindtijd'], 0, 5); ?></td>
                                            <td class="py-2 px-4 border">
                                                <a href="?edit=<?php echo $uitgiftedag['id']; ?>" class="text-blue-500 hover:text-blue-700">
                                                    Wijzigen
                                                </a>
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
