#!/bin/bash

# Naam van de database
DB_FILE=${1-product-uitgifte.db}

# Verwijder bestaande database
rm -f "$DB_FILE"

# Maak nieuwe database en tabellen
sqlite3 "$DB_FILE" <<EOF
-- Tabel voor producten
CREATE TABLE IF NOT EXISTS producten (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    naam TEXT NOT NULL UNIQUE
);

-- Tabel voor uitgiftedata
CREATE TABLE IF NOT EXISTS uitgiftedatum (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uitgiftedatum TEXT NOT NULL UNIQUE,
    starttijd TEXT NOT NULL,
    eindtijd TEXT NOT NULL
);

-- Tabel voor leden
CREATE TABLE IF NOT EXISTS leden (
    certificaat INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL,
    monden INTEGER NOT NULL,
    FOREIGN KEY(product_id) REFERENCES producten(id)
);

-- Tabel voor registraties
CREATE TABLE IF NOT EXISTS registraties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificaat INTEGER NOT NULL,
    gebruiker TEXT NOT NULL,
    registratie_tijd TEXT NOT NULL,
    uitgiftedag INTEGER NOT NULL,
    FOREIGN KEY(certificaat) REFERENCES leden(certificaat),
    FOREIGN KEY(uitgiftedag) REFERENCES uitgiftedatum(id)
);

EOF

echo "Database $DB_FILE is aangemaakt."
