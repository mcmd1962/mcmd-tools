<?php
// Start de sessie
session_start();

// Inclusief configuratiebestand
require_once 'product-config.php';
require_once 'product-functions.php';

// Maak verbinding met de database
$db = new SQLite3($dbFile);

// Haal statistieken op
$ledenCount = getLedenCount($db);
$productenCount = getProductenCount($db);
$uitgiftedagenCount = getUitgiftedagenCount($db);
$registratiesCount = getRegistratiesCount($db);

// Haal de eerstvolgende uitgiftedag op
$volgendeUitgiftedag = getVolgendeUitgiftedag($db);
$uitgifteStatus = getUitgifteStatus($volgendeUitgiftedag);

// Sluit de databaseverbinding
$db->close();

$paginaTitel = "Product Uitgiftesysteem";
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
        .card {
            transition: all 0.3s ease;
            border-radius: 0.5rem;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .stat-card {
            border-left: 4px solid;
            border-radius: 0.25rem;
        }
        .stat-card.blue { border-left-color: #3b82f6; }
        .stat-card.green { border-left-color: #10b981; }
        .stat-card.purple { border-left-color: #8b5cf6; }
        .stat-card.orange { border-left-color: #f59e0b; }
        .bg-gradient {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }
        .next-event {
            border-left: 4px solid #3b82f6;
            background-color: rgba(59, 130, 246, 0.05);
        }
        .open-status {
            color: #10b981;
        }
        .closed-status {
            color: #ef4444;
        }
        .upcoming-status {
            color: #f59e0b;
        }
        .countdown {
            font-family: 'Courier New', monospace;
            font-weight: bold;
        }
        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-open {
            background-color: #10b981;
        }
        .status-closed {
            background-color: #ef4444;
        }
        .status-upcoming {
            background-color: #f59e0b;
        }
    </style>
</head>
<body class="bg-gray-50 font-sans leading-normal tracking-normal">
    <div class="bg-gradient min-h-screen">
        <div class="container mx-auto px-4 py-12">
            <!-- Header -->
            <header class="mb-12">
                <div class="flex flex-col md:flex-row justify-between items-center">
                    <div class="mb-6 md:mb-0">
                        <h1 class="text-3xl font-bold text-gray-800">Product Uitgiftesysteem</h1>
                        <p class="text-gray-600">Beheer en registratie van productuitgifte</p>
                    </div>
                    <div class="text-right">
                        <p class="text-gray-700"><i class="fas fa-user mr-2"></i>Ingelogd als: <span class="font-semibold"><?php echo htmlspecialchars(getGebruikersnaam()); ?></span></p>
                        <p class="text-sm text-gray-500"><?php echo date('d-m-Y H:i'); ?></p>
                    </div>
                </div>
            </header>

            <!-- Volgende uitgiftedag informatie -->
            <div class="next-event p-6 mb-8 rounded-lg shadow-sm">
                <div class="flex flex-col md:flex-row justify-between items-start md:items-center">
                    <div class="mb-4 md:mb-0">
                        <h2 class="text-xl font-semibold text-gray-800 mb-2 flex items-center">
                            <i class="fas fa-calendar-check text-blue-500 mr-2"></i>
                            Volgende uitgifte
                        </h2>

                        <?php if ($volgendeUitgiftedag): ?>
                            <div class="flex items-center mb-1">
                                <span class="status-indicator
                                    <?php echo $uitgifteStatus['isOpen'] ? 'status-open' :
                                          ($uitgifteStatus['status'] == 'afgelopen' ? 'status-closed' : 'status-upcoming'); ?>">
                                </span>
                                <span class="font-semibold">
                                    <?php echo date('d-m-Y', strtotime($volgendeUitgiftedag['uitgiftedatum'])); ?>
                                </span>
                            </div>

                            <div class="flex items-center text-gray-700">
                                <i class="fas fa-clock mr-2 text-gray-500"></i>
                                <?php echo substr($volgendeUitgiftedag['starttijd'], 0, 5); ?> -
                                <?php echo substr($volgendeUitgiftedag['eindtijd'], 0, 5); ?>
                            </div>

                            <div class="mt-2 flex items-center">
                                <?php if ($uitgifteStatus['isVandaag']): ?>
                                    <span class="<?php echo $uitgifteStatus['isOpen'] ? 'open-status' : 'closed-status'; ?>">
                                        <?php if ($uitgifteStatus['isOpen']): ?>
                                            <i class="fas fa-door-open mr-1"></i> Nu open voor registraties
                                        <?php elseif ($uitgifteStatus['status'] == 'toekomstig'): ?>
                                            <i class="fas fa-clock mr-1"></i> <?php echo $uitgifteStatus['message']; ?>
                                        <?php else: ?>
                                            <i class="fas fa-door-closed mr-1"></i> Afgelopen
                                        <?php endif; ?>
                                    </span>
                                <?php else: ?>
                                    <span class="upcoming-status">
                                        <i class="fas fa-calendar-day mr-1"></i> <?php echo $uitgifteStatus['message']; ?>
                                    </span>
                                <?php endif; ?>
                            </div>
                        <?php else: ?>
                            <div class="text-gray-600">
                                <i class="fas fa-info-circle mr-1"></i> Geen geplande uitgiftes gevonden
                            </div>
                        <?php endif; ?>
                    </div>

                    <?php if ($volgendeUitgiftedag && !$uitgifteStatus['isVandaag'] && $uitgifteStatus['status'] != 'afgelopen'): ?>
                        <div class="countdown text-right md:text-left md:ml-4">
                            <?php
                            $nu = new DateTime();
                            $eerstvolgende = new DateTime($volgendeUitgiftedag['uitgiftedatum'] . ' ' . $volgendeUitgiftedag['starttijd']);
                            $verschil = $nu->diff($eerstvolgende);

                            if ($verschil->invert == 0) {
                                echo "<div class='text-sm text-gray-600 mb-1'>Over</div>";
                                if ($verschil->days > 0) {
                                    echo "<div class='text-lg font-bold'>" . $verschil->days . " dagen</div>";
                                } elseif ($verschil->h > 0) {
                                    echo "<div class='text-lg font-bold'>" . $verschil->h . " uur</div>";
                                } else {
                                    echo "<div class='text-lg font-bold'>" . $verschil->i . " minuten</div>";
                                }
                            }
                            ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Statistieken -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                <div class="stat-card blue bg-white p-6">
                    <div class="flex items-center">
                        <div class="p-3 bg-blue-100 rounded-full mr-4">
                            <i class="fas fa-users text-blue-500"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Totaal leden</p>
                            <p class="text-2xl font-bold"><?php echo $ledenCount; ?></p>
                        </div>
                    </div>
                </div>

                <div class="stat-card green bg-white p-6">
                    <div class="flex items-center">
                        <div class="p-3 bg-green-100 rounded-full mr-4">
                            <i class="fas fa-boxes text-green-500"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Producten</p>
                            <p class="text-2xl font-bold"><?php echo $productenCount; ?></p>
                        </div>
                    </div>
                </div>

                <div class="stat-card purple bg-white p-6">
                    <div class="flex items-center">
                        <div class="p-3 bg-purple-100 rounded-full mr-4">
                            <i class="fas fa-calendar-alt text-purple-500"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Uitgiftedagen</p>
                            <p class="text-2xl font-bold"><?php echo $uitgiftedagenCount; ?></p>
                        </div>
                    </div>
                </div>

                <div class="stat-card orange bg-white p-6">
                    <div class="flex items-center">
                        <div class="p-3 bg-orange-100 rounded-full mr-4">
                            <i class="fas fa-clipboard-list text-orange-500"></i>
                        </div>
                        <div>
                            <p class="text-gray-500 text-sm">Registraties</p>
                            <p class="text-2xl font-bold"><?php echo $registratiesCount; ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Hoofdmenu -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <!-- Product Uitgifte -->
                <div class="card bg-white p-6 shadow-md hover:shadow-lg">
                    <div class="flex items-center mb-4">
                        <div class="p-3 bg-blue-100 rounded-full mr-4">
                            <i class="fas fa-exchange-alt text-blue-500 text-xl"></i>
                        </div>
                        <h2 class="text-xl font-semibold text-gray-800">Product Uitgifte</h2>
                    </div>
                    <p class="text-gray-600 mb-6">Registreer de uitgifte van producten en bekijk de huidige status.</p>
                    <a href="product-uitgifte.php" class="inline-block bg-blue-500 hover:bg-blue-600 text-white font-medium py-2 px-4 rounded transition duration-200">
                        <i class="fas fa-arrow-right mr-2"></i>Open Product Uitgifte
                    </a>
                </div>

                <!-- Leden Beheer -->
                <div class="card bg-white p-6 shadow-md hover:shadow-lg">
                    <div class="flex items-center mb-4">
                        <div class="p-3 bg-green-100 rounded-full mr-4">
                            <i class="fas fa-users text-green-500 text-xl"></i>
                        </div>
                        <h2 class="text-xl font-semibold text-gray-800">Leden Beheer</h2>
                    </div>
                    <p class="text-gray-600 mb-6">Beheer de leden met hun certificaten, producten en gegevens.</p>
                    <a href="muteer-leden.php" class="inline-block bg-green-500 hover:bg-green-600 text-white font-medium py-2 px-4 rounded transition duration-200">
                        <i class="fas fa-arrow-right mr-2"></i>Open Leden Beheer
                    </a>
                </div>

                <!-- Registraties Beheer -->
                <div class="card bg-white p-6 shadow-md hover:shadow-lg">
                    <div class="flex items-center mb-4">
                        <div class="p-3 bg-purple-100 rounded-full mr-4">
                            <i class="fas fa-clipboard-list text-purple-500 text-xl"></i>
                        </div>
                        <h2 class="text-xl font-semibold text-gray-800">Registraties Beheer</h2>
                    </div>
                    <p class="text-gray-600 mb-6">Beheer en bekijk alle registraties van productuitgifte.</p>
                    <a href="muteer-registraties.php" class="inline-block bg-purple-500 hover:bg-purple-600 text-white font-medium py-2 px-4 rounded transition duration-200">
                        <i class="fas fa-arrow-right mr-2"></i>Open Registraties Beheer
                    </a>
                </div>

                <!-- Uitgiftedagen Beheer -->
                <div class="card bg-white p-6 shadow-md hover:shadow-lg">
                    <div class="flex items-center mb-4">
                        <div class="p-3 bg-orange-100 rounded-full mr-4">
                            <i class="fas fa-calendar-alt text-orange-500 text-xl"></i>
                        </div>
                        <h2 class="text-xl font-semibold text-gray-800">Uitgiftedagen Beheer</h2>
                    </div>
                    <p class="text-gray-600 mb-6">Beheer de dagen waarop producten uitgegeven worden.</p>
                    <a href="muteer-uitgiftedagen.php" class="inline-block bg-orange-500 hover:bg-orange-600 text-white font-medium py-2 px-4 rounded transition duration-200">
                        <i class="fas fa-arrow-right mr-2"></i>Open Uitgiftedagen Beheer
                    </a>
                </div>

                <!-- Rapportages -->
                <div class="card bg-white p-6 shadow-md hover:shadow-lg">
                    <div class="flex items-center mb-4">
                        <div class="p-3 bg-red-100 rounded-full mr-4">
                            <i class="fas fa-chart-bar text-red-500 text-xl"></i>
                        </div>
                        <h2 class="text-xl font-semibold text-gray-800">Rapportages</h2>
                    </div>
                    <p class="text-gray-600 mb-6">Bekijk en genereer rapportages van de productuitgifte.</p>
                    <a href="product-uitgifte-rapport.php" class="inline-block bg-red-500 hover:bg-red-600 text-white font-medium py-2 px-4 rounded transition duration-200">
                        <i class="fas fa-arrow-right mr-2"></i>Open Rapportages
                    </a>
                </div>
            </div>

            <!-- Voettekst -->
            <footer class="mt-16 text-center text-gray-500 text-sm">
                <p>Product Uitgiftesysteem &copy; <?php echo date('Y'); ?> | Gebruiker: <?php echo htmlspecialchars(getGebruikersnaam()); ?></p>
            </footer>
        </div>
    </div>
</body>
</html>
