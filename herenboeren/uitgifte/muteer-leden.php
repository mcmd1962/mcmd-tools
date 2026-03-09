<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';
require_once 'product-functions.php';

// Maak of open de SQLite database
$db = new SQLite3($dbFile);

// Haal alle producten en leden op
$producten = getProducten($db);
$leden = getLeden($db);

// Verwerk formuliereacties
$message = '';
$messageType = ''; // success, error, info

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        $action = $_POST['action'];

        if ($action === 'toevoegen') {
            $certificaat = $_POST['certificaat'];
            $product_id = $_POST['product_id'];
            $monden = $_POST['monden'];
            $naam = $_POST['naam'];

            $result = voegLidToe($db, $certificaat, $product_id, $monden, $naam);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de ledenlijst
                $leden = getLeden($db);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
        elseif ($action === 'wijzigen') {
            $leden_id = $_POST['leden_id'];
            $certificaat = $_POST['certificaat'];
            $product_id = $_POST['product_id'];
            $monden = $_POST['monden'];
            $naam = $_POST['naam'];

            $result = wijzigLid($db, $leden_id, $certificaat, $product_id, $monden, $naam);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de ledenlijst
                $leden = getLeden($db);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
        elseif ($action === 'verwijderen') {
            $leden_id = $_POST['leden_id'];

            $result = verwijderLid($db, $leden_id);
            if ($result['success']) {
                $message = $result['message'];
                $messageType = 'success';
                // Vernieuw de ledenlijst
                $leden = getLeden($db);
            } else {
                $message = $result['message'];
                $messageType = 'error';
            }
        }
    }
}

// Haal het lid voor bewerken als er een edit_id is
$editLid = null;
if (isset($_GET['edit']) && is_numeric($_GET['edit'])) {
    $leden_id = $_GET['edit'];
    $stmt = $db->prepare("
        SELECT l.leden_id, l.certificaat, l.product_id, l.monden, l.naam, p.naam as product_naam
        FROM leden l
        JOIN producten p ON l.product_id = p.product_id
        WHERE l.leden_id = :leden_id
    ");
    $stmt->bindValue(':leden_id', $leden_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $editLid = $result->fetchArray(SQLITE3_ASSOC);
}

$paginaTitel = "Leden Beheer";
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

    <div class="container w-full mx-auto pt-10 pb-1">
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

    <div class="container w-full mx-auto pt-2">

    <div class="container w-full mx-auto pt-0 pb-10">
        <div class="w-full px-4 text-xl text-gray-800 leading-normal">
            <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">

                <!-- Berichten weergave -->
                <?php if (!empty($message)): ?>
                    <div class="message <?php echo $messageType; ?>">
                        <?php echo $message; ?>
                    </div>
                <?php endif; ?>

                <!-- Lid toevoegen/wijzigen formulier -->
                <div class="mb-8 p-4 border rounded-lg bg-gray-50">
                    <h2 class="text-xl font-bold mb-4">
                        <?php echo $editLid ? 'Lid Wijzigen' : 'Nieuw Lid Toevoegen'; ?>
                    </h2>

                    <form method="POST" action="">
                        <input type="hidden" name="action" value="<?php echo $editLid ? 'wijzigen' : 'toevoegen'; ?>">

                        <?php if ($editLid): ?>
                            <input type="hidden" name="leden_id" value="<?php echo $editLid['leden_id']; ?>">
                        <?php endif; ?>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="certificaat">
                                    Certificaatnummer
                                </label>
                                <input type="number" id="certificaat" name="certificaat"
                                       class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                       value="<?php echo $editLid ? $editLid['certificaat'] : ''; ?>" required>
                            </div>

                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="product_id">
                                    Product
                                </label>
                                <select id="product_id" name="product_id"
                                        class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" required>
                                    <option value="">Selecteer een product</option>
                                    <?php foreach ($producten as $product): ?>
                                        <option value="<?php echo $product['product_id']; ?>"
                                            <?php echo ($editLid && $editLid['product_id'] == $product['product_id']) ? 'selected' : ''; ?>>
                                            <?php echo $product['naam']; ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="monden">
                                    Aantal Monden
                                </label>
                                <input type="number" id="monden" name="monden" min="1"
                                       class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                       value="<?php echo $editLid ? $editLid['monden'] : '1'; ?>" required>
                            </div>

                            <div>
                                <label class="block text-gray-700 text-sm font-bold mb-2" for="naam">
                                    Naam
                                </label>
                                <input type="text" id="naam" name="naam"
                                       class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                                       value="<?php echo $editLid ? $editLid['naam'] : ''; ?>">
                            </div>
                        </div>

                        <div class="flex items-center justify-between">
                            <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline">
                                <?php echo $editLid ? 'Wijzigen' : 'Toevoegen'; ?>
                            </button>

                            <?php if ($editLid): ?>
                                <a href="muteer-leden.php" class="inline-block align-baseline font-bold text-sm text-blue-500 hover:text-blue-800">
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

                <!-- Leden overzicht -->
                <div class="mb-6">
                    <h2 class="text-xl font-bold mb-4">Leden Overzicht</h2>

                    <div class="overflow-x-auto">
                        <table class="min-w-full bg-white border border-gray-300">
                            <thead>
                                <tr class="bg-gray-100">
                                    <th class="py-2 px-4 border">Certificaat</th>
                                    <th class="py-2 px-4 border">Naam</th>
                                    <th class="py-2 px-4 border">Product</th>
                                    <th class="py-2 px-4 border">Monden</th>
                                    <th class="py-2 px-4 border">Acties</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($leden)): ?>
                                    <tr>
                                        <td colspan="5" class="py-2 px-4 border text-center">Geen leden gevonden</td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($leden as $lid): ?>
                                        <tr class="<?php echo ($lid['certificaat'] % 2 == 0) ? 'bg-gray-50' : ''; ?>">
                                            <td class="py-2 px-4 border"><?php echo $lid['certificaat']; ?></td>
                                            <td class="py-2 px-4 border"><?php echo !empty($lid['naam']) ? $lid['naam'] : '-'; ?></td>
                                            <td class="py-2 px-4 border"><?php echo $lid['product_naam']; ?></td>
                                            <td class="py-2 px-4 border"><?php echo $lid['monden']; ?></td>
                                            <td class="py-2 px-4 border">
                                                <a href="?edit=<?php echo $lid['leden_id']; ?>" class="text-blue-500 hover:text-blue-700 mr-2">Wijzigen</a>
                                                <form method="POST" action="" class="inline">
                                                    <input type="hidden" name="action" value="verwijderen">
                                                    <input type="hidden" name="leden_id" value="<?php echo $lid['leden_id']; ?>">
                                                    <button type="submit" class="text-red-500 hover:text-red-700" onclick="return confirm('Weet je zeker dat je dit lid wilt verwijderen?')">Verwijderen</button>
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
