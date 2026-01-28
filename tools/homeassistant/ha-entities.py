#!/usr/bin/env python3

import argparse
import datetime
import psycopg2
import re

__author__ = 'MD'
__copyright__ = 'Copyright 2026, MD'
__license__ = 'MIT'
__version__ = '2025-12.01'


def get_arguments():
    """
    get commandline arguments
    """

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Schat de schijfruimte per entiteit in Home Assistant's PostgreSQL database.")
    parser.add_argument(
        '--start-days-ago',
        type=int,
        default=99,
        help='Aantal dagen geleden om records vanaf te tellen (standaard: %(default)s)',
    )
    parser.add_argument(
        '--end-days-ago',
        type=int,
        default=-1,
        help='Aantal dagen geleden om records tot te tellen (standaard: %(default)s)',
    )

    parser.add_argument(
        '--min-records',
        '--min',
        type=str,
        default='0',
        help='Minimaal aantal records per entiteit (bijv. "234" of "gemiddeld", standaard: %(default)s)',
    )
    parser.add_argument(
        '--max-records',
        '--max',
        type=str,
        default='10000000',
        help='Maximaal aantal records per entiteit (bijv. "234" of "gemiddeld", standaard: %(default)s)',
    )

    parser.add_argument(
        '--min-records-rate',
        type=int,
        default=0,
        help='Minimaal aantal records per hour per entiteit (bijv. "234", standaard: %(default)s)',
    )
    parser.add_argument(
        '--max-records-rate',
        type=int,
        default=100000,
        help='Maximaal aantal records per hour per entiteit (bijv. "234", standaard: %(default)s)',
    )

    parser.add_argument(
        '--entity-filter',
        type=str,
        default='.*',
        help="Regex-filter voor entiteitsnamen (bijv. '^sensor.*' of '.*temperature.*', standaard: %(default)s)",
    )
    parser.add_argument(
        '--show-last-value',
        action='store_true',
        help='Toon de waarde van een entiteit.',
    )
    parser.add_argument(
        '--show-timestamps',
        action='store_true',
        help='Toon het tijdstip van het eerste en laatste record per entiteit.',
    )
    parser.add_argument(
        '--sort-key-column',
        type=int,
        help='Sort output based on column: 0: entity_name; 1: count records; 2: count rate records; 3: timestamp first record; 4: timestamp last record; 5: value',
    )
    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)

    return parser.parse_args()


args = get_arguments()

# Bereken de start- en einddatum in Unix timestamp (seconden sinds epoch)
end_date = (datetime.datetime.now() - datetime.timedelta(days=args.end_days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)
end_date_ts = end_date.timestamp()
end_date = end_date.strftime('%Y-%m-%d')

start_date = (datetime.datetime.now() - datetime.timedelta(days=args.start_days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)
start_date_ts = start_date.timestamp()
start_date = start_date.strftime('%Y-%m-%d')

# Database verbindingsgegevens
db_host = 'localhost'
db_name = 'home_assistant_v2'
db_user = 'USER'

# Verbinding maken met de database
conn = psycopg2.connect(host=db_host, database=db_name, user=db_user)
cursor = conn.cursor()

# Query om het totaal aantal records in het opgegeven tijdsbereik op te halen
query_count = f' SELECT COUNT(*) FROM states WHERE last_updated_ts BETWEEN {start_date_ts} AND {end_date_ts};'
cursor.execute(query_count)
total_records = cursor.fetchone()[0]

# Query om het aantal entiteiten in het opgegeven tijdsbereik op te halen
cursor.execute(
    """
    SELECT COUNT(DISTINCT sm.entity_id)
    FROM states s
    JOIN states_meta sm ON s.metadata_id = sm.metadata_id
    WHERE s.last_updated_ts BETWEEN %s AND %s;
    """,
    (start_date_ts, end_date_ts),
)
total_entities = cursor.fetchone()[0]

cursor.execute("""
    SELECT n_live_tup, n_dead_tup, pg_table_size('states') as table_size
    FROM pg_stat_user_tables
    WHERE relname = 'states';
""")
live_tupples, dead_tupples, table_size = cursor.fetchone()

# Schat de gemiddelde grootte per levend record
avg_record_size = table_size / live_tupples if live_tupples > 0 else 0

# Bepaal het gemiddelde aantal records per entiteit
avg_records_per_entity = total_records / total_entities if total_entities > 0 else 0

# Bepaal de drempelwaarde voor --min-records
if args.min_records.lower() == 'gemiddeld':
    min_records = int(avg_records_per_entity)
else:
    min_records = int(args.min_records)

# Bepaal de drempelwaarde voor --min-records
if args.max_records.lower() == 'gemiddeld':
    max_records = int(avg_records_per_entity)
else:
    max_records = int(args.max_records)

# Filter de resultaten op basis van min_records en entity_filter
entity_regex = re.compile(args.entity_filter)

# Query om het aantal records per entiteit in het opgegeven tijdsbereik op te halen
query = """
    WITH last_states AS (
        SELECT
            sm.entity_id,
            s.state,
            ROW_NUMBER() OVER (PARTITION BY sm.entity_id ORDER BY s.last_updated_ts DESC) as rn
        FROM
            states s
        JOIN
            states_meta sm ON s.metadata_id = sm.metadata_id
        WHERE
            s.last_updated_ts BETWEEN %s AND %s
    ),
    entity_stats AS (
        SELECT
            sm.entity_id,
            COUNT(*) as record_count,
            MIN(s.last_updated_ts) as first_timestamp,
            MAX(s.last_updated_ts) as last_timestamp
        FROM
            states s
        JOIN
            states_meta sm ON s.metadata_id = sm.metadata_id
        WHERE
            s.last_updated_ts BETWEEN %s AND %s
        GROUP BY
            sm.entity_id
    )
    SELECT
        es.entity_id,
        es.record_count,
        es.first_timestamp,
        es.last_timestamp,
        ls.state as last_state
    FROM
        entity_stats es
    LEFT JOIN
        last_states ls ON es.entity_id = ls.entity_id AND ls.rn = 1
    ORDER BY
        es.record_count DESC;
"""

# Execute the query to retrieve the records
cursor.execute(query, (start_date_ts, end_date_ts, start_date_ts, end_date_ts))

# Resultaten ophalen en printen
results = cursor.fetchall()

# Filter de resultaten op basis van min_records & max_records
filtered_results = [row for row in results if row[1] >= min_records and row[1] <= max_records and entity_regex.search(row[0])]

new_filtered_results = []
for record in filtered_results:
    entity_id, record_count, first_ts, last_ts, last_state = record

    if last_ts == first_ts:
        records_per_hour = 0
    else:
        records_per_hour = min(record_count, record_count / (last_ts - first_ts) * 3600.0)
    new_record = (record[0], record[1], records_per_hour, *record[2:])
    include_record = records_per_hour >= args.min_records_rate and records_per_hour <= args.max_records_rate
    if include_record:
        new_filtered_results.append(new_record)

filtered_results = new_filtered_results

if args.sort_key_column is not None and args.sort_key_column != 1:
    filtered_results.sort(key=lambda x: x[args.sort_key_column], reverse=(args.sort_key_column == 2))

date_time_format = '%Y-%m-%d %H:%M:%S'
earliest_timestamp = min(row[2] for row in filtered_results) if filtered_results else None
earliest_timestamp = datetime.datetime.fromtimestamp(earliest_timestamp).strftime(date_time_format) if earliest_timestamp else None
latest_timestamp = max(row[3] for row in filtered_results) if filtered_results else None
latest_timestamp = datetime.datetime.fromtimestamp(latest_timestamp).strftime(date_time_format) if latest_timestamp else None


# Bepaal de totalen voor de gefilterde resultaten
total_filtered_records = sum(row[1] for row in filtered_results)
total_filtered_entities = len(filtered_results)
avg_filtered_records_per_entity = total_filtered_records / total_filtered_entities if total_filtered_entities > 0 else 0


# Entiteit: binary_sensor.volvo_v60_cross_country_daytime_running_light_right, Aantal records: 2
max_entity_length = max(len(row[0]) for row in filtered_results)
max_count_length = max(len(str(row[1])) for row in filtered_results)
max_size_length = max(
    max(len(f'{row[1] * avg_record_size / (1024**2):.2f} MB') for row in results),
    len('Geschatte ruimte'),
)

max_state_length = max(len(str(row[4])) for row in filtered_results) if filtered_results else 0

count_header_length = max(max_count_length, len('Aantal records'))
# Print de header
header = f'{"Entiteit":<{max_entity_length}} | {"Aantal records":>{count_header_length}} | {"Geschatte ruimte":>{max_size_length}}'
if args.show_timestamps:
    header += f' | {"Eerste record":<20} | {"Laatste record":<20}'
if args.show_last_value:
    header += f' | {"Laatste waarde":<20}'

print('Records gefiltered op de volgende criteria:')
print(f'- tussen {start_date} en {end_date}')
print(f'- minimaal {min_records} records per entiteit')
print(f'- maximaal {max_records} records per entiteit')
print(f"- entiteit-filter: '{args.entity_filter}'")
print()
print(header)
print('-' * len(header))

# Print de resultaten met dynamische formatering en schijfruimte schatting
for row in filtered_results:
    entity_id, record_count, records_per_hour, first_ts, last_ts, last_state = row
    estimated_size_kb = (record_count * avg_record_size) / (1024**1)
    estimated_size_mb = (record_count * avg_record_size) / (1024**2)
    first_timestamp = datetime.datetime.fromtimestamp(first_ts).strftime(date_time_format)
    last_timestamp = datetime.datetime.fromtimestamp(last_ts).strftime(date_time_format)

    records_per_hour_length = count_header_length - max_count_length - 1
    records_info = f'{record_count:>{max_count_length}} {records_per_hour:{records_per_hour_length}.1f}'

    line = f'{entity_id:<{max_entity_length}} | {records_info:>{count_header_length}} | {estimated_size_kb:>{max_size_length - 3}.0f} KB'
    if args.show_timestamps:
        line += f' | {first_timestamp:<20} | {last_timestamp:<20s}'
    if last_state is None:
        last_state = '∅'
    if args.show_last_value:
        line += f' | {last_state:>14}'
    print(line)


# Print de totale grootte van de gefilterde states tabel voor het opgegeven tijdsbereik
print(f'\nTotaal (gefilterd, in opgegeven bereik: {earliest_timestamp}  -  {latest_timestamp}):')
percentage_filtered_records = total_filtered_records / total_records * 100
print(f'  Aantal records                       : {total_filtered_records:7d}    (={percentage_filtered_records:5.1f}%)')
percentage_filtered_entities = total_filtered_entities / total_entities * 100
print(f'  Aantal entiteiten                    : {total_filtered_entities:7d}    (={percentage_filtered_entities:5.1f}%)')
print(f'  Gemiddeld aantal records per entiteit: {avg_filtered_records_per_entity:7.0f}')
print(f'  Gemiddelde recordgrootte (hele tabel): {avg_record_size:7.0f} bytes')

percentage_filtered_size = total_filtered_records * avg_record_size / table_size * 100
filtered_size = total_filtered_records * avg_record_size / 1024**2
print(f'  Geschatte totale ruimte (gefilterd)  : {filtered_size:7.0f} MB (={percentage_filtered_size:5.1f}%)')


# Verbinding sluiten
cursor.close()
conn.close()
