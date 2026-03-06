#!/bin/bash

# Naam van de database
DATABASE=${1-product-registratie-website.db}

[[ ! -f $DATABASE ]] && exit 1

function invoer_registraties() {
  echo "DELETE FROM registraties;"
}

function invoer_uitgiftedatum() {
  echo "DELETE FROM uitgiftedatum;"
  echo "INSERT INTO uitgiftedatum (uitgiftedatum, starttijd, eindtijd) VALUES ('$(date +%Y-%m-%d)', '00:00:00', '23:59:59');"
}

function invoer_producten() {
  echo "DELETE FROM producten;"
  echo "insert into producten(naam) values ('groente');"
  echo "insert into producten(naam) values ('vlees');"
}

function invoer_leden() {
  echo "DELETE FROM leden;"
  for nummer in $(seq 1 1 140); do
    product_id=$((1 + $RANDOM % 2))
    hoeveelheid=$((1 + $RANDOM % 6))
    echo "insert into leden(nummer,product_id,hoeveelheid) values ($nummer,$product_id,$hoeveelheid);"
  done
}

function generate_sql() {
  echo "BEGIN TRANSACTION;"
  invoer_registraties
  invoer_uitgiftedatum
  invoer_producten
  invoer_leden
  echo "COMMIT;"
}

# Voer de SQL-instructies uit
generate_sql | sqlite3 "$DATABASE"

# Controleer of de operatie geslaagd is
if [ $? -eq 0 ]; then
  echo "Gegevens zijn succesvol in de database geplaatst."
else
  echo "Er is een fout opgetreden bij het plaatsen van de gegevens." >&2
fi
