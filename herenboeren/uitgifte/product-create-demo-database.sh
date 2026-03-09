#!/bin/bash
# vim: set autoindent filetype=sh tabstop=3 shiftwidth=3 softtabstop=3 number textwidth=175 expandtab:

# Naam van de database
DATABASE=${1-product-registratie-website.db}

./product-create-database.sh $DATABASE

[[ ! -f $DATABASE ]] && exit 1

AANTAL_CERTIFICATEN=99

function invoer_registraties() {
   echo "DELETE FROM registraties;"
   # INSERT INTO registraties VALUES(1,1,'Anoniem','2026-03-07 18:49:38',1);
   #  id INTEGER PRIMARY KEY AUTOINCREMENT,
   #  certificaat INTEGER NOT NULL,
   #  gebruiker TEXT NOT NULL,
   #  registratie_tijd TEXT NOT NULL,
   #  uitgiftedag INTEGER NOT NULL,

   uitgiftedag=0
   gebruiker="onbekend"
   for i in $(seq 1 7 35); do
      uitgiftedag=$(($uitgiftedag + 1))
      DAY=$(gdate -d "$i days ago" "+%Y-%m-%d 12:12:12")
      DAY_CHANCE=$(($RANDOM % 50 + 55))
      for certificaat in $(seq 1 1 $AANTAL_CERTIFICATEN); do
         if [[ $(($RANDOM % 100)) -lt $DAY_CHANCE ]]; then
            echo "INSERT INTO registraties (leden_id, gebruiker, registratie_tijd,uitgiftedag) VALUES($certificaat,'$gebruiker','$DAY',$uitgiftedag);"
         fi
      done
   done
}

function invoer_uitgiftedatum() {
   echo "DELETE FROM uitgiftedatum;"
   for i in $(seq 1 7 35); do
      DAY=$(gdate -d "+$i days ago" +%Y-%m-%d)
      echo "INSERT INTO uitgiftedatum (uitgiftedatum, starttijd, eindtijd) VALUES ('$DAY', '00:00:00', '23:59:59');"
   done
   for i in $(seq 0 1 28); do
      DAY=$(gdate -d "+$i days" +%Y-%m-%d)
      echo "INSERT INTO uitgiftedatum (uitgiftedatum, starttijd, eindtijd) VALUES ('$DAY', '00:00:00', '23:59:59');"
   done
}

function invoer_producten() {
   echo "DELETE FROM producten;"
   echo "insert into producten(naam) values ('groente');"
   echo "insert into producten(naam) values ('vlees');"
}

function invoer_leden() {
   echo "DELETE FROM leden;"
   for certificaat in $(seq 1 1 $AANTAL_CERTIFICATEN); do
      product_id=$((1 + $RANDOM % 2))
      monden=$((1 + $RANDOM % 6))
      echo "insert into leden(certificaat,product_id,naam,monden) values ($certificaat,$product_id,'gebruiker-$certificaat',$monden);"
   done
}

function generate_sql() {
   echo "BEGIN TRANSACTION;"
   invoer_uitgiftedatum
   invoer_producten
   invoer_leden
   invoer_registraties
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
