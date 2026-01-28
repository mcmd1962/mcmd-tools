#!/usr/bin/env python3
# vim: set autoindent filetype=python tabstop=4 shiftwidth=4 softtabstop=4 number textwidth=175 expandtab:

import argparse

# import datetime
from datetime import datetime, timedelta
import psycopg2
import sys

from typing import Any

__author__ = 'MD'
__copyright__ = 'Copyright 2026, MD'
__license__ = 'MIT'
__version__ = '2026-01.01'


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
        '--threshold',
        type=int,
        default=0,
        help='Threshold, below threshold is tagged as LOW (standaard: %(default)s)',
    )

    parser.add_argument(
        '--tolerance',
        '-t',
        type=float,
        default=0.0,
        help='Tolerantie in sequential status waarden (standaard: %(default)s)',
    )

    parser.add_argument(
        '--tolerance-percentage',
        '-T',
        type=int,
        default=0,
        help='Tolerantie in procenten in sequential status waarden (standaard: %(default)s)',
    )

    parser.add_argument(
        '--entity',
        type=str,
        required=True,
        help="Entity (bijv. 'sensor.hue_motion_3_battery', verplicht om te geven",
    )
    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)

    return parser.parse_args()


def get_normalized_status_value(x):
    try:
        x = float(x)
    except ValueError:
        pass

    return x


def getInToleranceRange(
    status: Any,
    previous_state: Any,
    min_status,
    max_status,
    tolerance: float,
    tolerance_percentage: int,
):
    status_value = get_normalized_status_value(x=status)
    if not isinstance(status, float):
        return min_status, max_status, status == previous_state

    if not isinstance(previous_state, float):
        return min_status, max_status, status == previous_state

    if not isinstance(min_status, float):
        min_status = status_value

    if not isinstance(max_status, float):
        max_status = status_value

    new_min_status = min(min_status, status_value)
    new_max_status = max(max_status, status_value)

    if abs(new_max_status - new_min_status) <= tolerance:
        return new_min_status, new_max_status, True

    ratio_min_max = 100.0 * (new_max_status - new_min_status) / new_max_status
    if ratio_min_max <= tolerance_percentage:
        return new_min_status, new_max_status, True

    return min_status, max_status, False


def get_normalized_duration(duration: float):
    normalized_duration = ''

    if duration > 3600:
        duration_hours = int(duration / 3600)
        duration = duration - duration_hours * 3600
        normalized_duration = f'{duration_hours}h'

    if len(normalized_duration) > 0 or (duration > 60):
        duration_minutes = int(duration / 60)
        duration = duration - duration_minutes * 60
        if len(normalized_duration) == 0:
            normalized_duration += f'{duration_minutes}m'
        else:
            normalized_duration += f'{duration_minutes:02d}m'

    if len(normalized_duration) == 0:
        normalized_duration += f'{duration:1.0f}s'
    else:
        normalized_duration += f'{duration:02.0f}s'

    return normalized_duration


def print_record(date_start: int, date_end: int, min_status: Any, max_status: Any, states_count: int):
    date_time_format = '%Y-%m-%d %H:%M:%S'

    date_start_format = datetime.fromtimestamp(date_start).strftime(date_time_format)
    delta_time = get_normalized_duration(duration=(date_end - date_start))

    if min_status == max_status:
        print(f'{date_start_format} {delta_time:>10s}  {states_count:5d}x   ->  {str(max_status):>19s}')
    else:
        print(f'{date_start_format} {delta_time:>10s}  {states_count:5d}x   ->  {str(min_status):>8s} - {str(max_status):>8s}')


args = get_arguments()

# Bereken de start- en einddatum in Unix timestamp (seconden sinds epoch)
end_date = (datetime.now() - timedelta(days=args.end_days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)
end_date_ts = end_date.timestamp()
end_date = end_date.strftime('%Y-%m-%d')

start_date = (datetime.now() - timedelta(days=args.start_days_ago)).replace(hour=0, minute=0, second=0, microsecond=0)
start_date_ts = start_date.timestamp()
start_date = start_date.strftime('%Y-%m-%d')

# Database verbindingsgegevens
db_host = 'localhost'
db_name = 'home_assistant_v2'
db_user = 'USER'

# Verbinding maken met de database
conn = psycopg2.connect(host=db_host, database=db_name, user=db_user)
cursor = conn.cursor()

# Query om het aantal entiteiten in het opgegeven tijdsbereik op te halen
query = f"""
    SELECT 
            last_updated_ts, state  
    FROM  
            states s 
    JOIN  
            states_meta sm ON s.metadata_id = sm.metadata_id 
    WHERE 
              sm.entity_id = '{args.entity}'  
          AND s.last_updated_ts BETWEEN {start_date_ts} and {end_date_ts}
    ORDER BY
              s.last_updated_ts;
    """


cursor.execute(query)
total_entities = cursor.fetchall()
cursor.close()
conn.close()

if len(total_entities) == 0:
    print('Niets gevonden')
    sys.exit()

first_record_date, first_record_state = total_entities[0]
first_record_state = get_normalized_status_value(x=first_record_state)
previous_state = first_record_state
previous_states = [first_record_state]
previous_states_count = 1
record_date = previous_date_start = previous_date_end = first_record_date
min_status = first_record_state
max_status = first_record_state

for record_date, record_state in total_entities[1:]:
    record_state = get_normalized_status_value(x=record_state)
    if isinstance(record_state, float) and record_state < args.threshold:
        record_state = 'LOW'

    min_status, max_status, isInToleranceRange = getInToleranceRange(
        status=record_state,
        previous_state=previous_state,
        min_status=min_status,
        max_status=max_status,
        tolerance=args.tolerance,
        tolerance_percentage=args.tolerance_percentage,
    )

    if isInToleranceRange:
        previous_states.append(record_state)
        previous_states_count += 1
        previous_date_end = record_date
        continue

    if previous_states_count == 1:
        previous_date_end = previous_date_start

    print_record(
        date_start=previous_date_start,
        date_end=record_date,
        states_count=previous_states_count,
        min_status=min_status,
        max_status=max_status,
    )
    previous_state = record_state
    previous_states_count = 1
    previous_states = [record_state]
    previous_date_start = record_date
    min_status = record_state
    max_status = record_state

print_record(
    date_start=previous_date_start,
    date_end=record_date,
    states_count=previous_states_count,
    min_status=min_status,
    max_status=max_status,
)
