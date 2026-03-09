#!/bin/bash

# Naam van de database
DB_FILE=${1-product-uitgifte.db}

# Verwijder bestaande database
rm -f "$DB_FILE"

# Maak nieuwe database en tabellen
sqlite3 "$DB_FILE" <<EOF
-- Tabel voor producten (met product_id als primary key)
CREATE TABLE IF NOT EXISTS producten (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
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
    leden_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
    certificaat INTEGER NOT NULL UNIQUE,
    product_id INTEGER NOT NULL,
    monden INTEGER NOT NULL,
    naam TEXT,
    FOREIGN KEY(product_id) REFERENCES producten(product_id)
);

-- Tabel voor registraties
CREATE TABLE IF NOT EXISTS registraties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    leden_id INTEGER NOT NULL,
    gebruiker TEXT NOT NULL,
    registratie_tijd TEXT NOT NULL,
    uitgiftedag INTEGER NOT NULL,
    FOREIGN KEY(leden_id) REFERENCES leden(leden_id),
    FOREIGN KEY(uitgiftedag) REFERENCES uitgiftedatum(id)
);
EOF

echo "Database $DB_FILE is aangemaakt."
