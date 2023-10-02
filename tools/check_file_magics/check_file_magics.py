#!/usr/bin/env python
# vim: set autoindent filetype=python tabstop=4 shiftwidth=4 softtabstop=4 number textwidth=175 expandtab:
'''
file integrity checking based on suffixes and known file magics
'''

import datetime
import hashlib
import pickle
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Union

import argparse
import collections
import json
import logging

import magic

__author__ = "Marcel Dorenbos"
__copyright__ = "Copyright 2023, Marcel Dorenbos"
__license__ = "MIT"
__version__ = "2023-09.01"

FileDataTupple = collections.namedtuple('FileDataTupple', 'path  name  magic_string  suffix  mtime')
SuffixMagicTupple = collections.namedtuple('SuffixMagicTupple', 'suffix  magic_string  count  oldest  newest  is_known_suffix_magic')
SuffixTupple = collections.namedtuple('SuffixTupple', 'suffix  count  errors  oldest  newest  is_known_suffix')

def get_arguments():
    """
    get commandline arguments
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="clean jobrun logfiles")

    default_config_file = Path(__file__).with_suffix('.json').name
    parser.add_argument("--config-file", help="Config file (default '%(default)s')", default=default_config_file, type=Path)
    parser.add_argument("--exceptions-file", help="Exception file (default '%(default)s')", type=Path)
    parser.add_argument("--directory", help="Directory to check files in (default '%(default)s')", type=Path,
                        default='/backup/amdbackup/amdbackup')
    parser.add_argument("--max-age", help="Max age of files to check (default '%(default)s')", type=int, default=21)
    choices = ['debug', 'info', 'warning', 'error', 'critical']
    parser.add_argument("--log", help="Set log level (default '%(default)s')", choices=choices, default="info")
    parser.add_argument("--generate-config-file", type=Path, help="generate config file from data")
    parser.add_argument("--generate-exceptions-file", type=Path, help="generate exceptions file from data")
    parser.add_argument("--error-report", action='store_true', help="report errors")
    parser.add_argument("--summary", action='store_true', help="report summary")
    parser.add_argument("--cache-data", action='store_true', help="cache data mode")
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

    return parser.parse_args()


def get_cache_filename(directory: Path, max_age: int, exceptions_file: Path) -> Path:
    '''
    get filename for cache file
    '''
    today = datetime.datetime.today().strftime('%Y%m%d-%H')
    hash_string = f'{__file__}-{directory}-{max_age}-{today}-{exceptions_file}'
    directory_max_age_hash = hashlib.new('sha256')
    directory_max_age_hash.update(hash_string.encode())
    return Path(f'/tmp/tmp-{Path(__file__).stem}-{directory_max_age_hash.hexdigest()}.pickle')

def get_count_files(recent_files: dict) -> tuple[int, int, int]:
    '''
    count the number of files in recent_files structure
    '''
    count_files = count_suffixes = count_magics = 0
    for suffix in recent_files:
        count_suffixes += 1
        for magic_string in recent_files[suffix]:
            count_magics += 1
            count_files += len(recent_files[suffix][magic_string])
    return count_files, count_suffixes, count_magics

def read_cached_data(cache_data_file: Path) -> dict:
    '''
    read cached data from file
    '''
    logging.debug('Started')
    if not cache_data_file.is_file():
        return {}

    with open(cache_data_file, 'rb') as file_in:
        recent_files = pickle.load(file_in)

    count_files, count_suffixes, count_magics = get_count_files(recent_files)

    logging.info('Using cached data in pickle file %s with %s suffixes and %s magics in %s files',
                  cache_data_file, count_suffixes, count_magics, count_files)
    logging.debug('Ended')
    return recent_files

def write_cached_data(cache_data_file: Path, data: dict) -> None:
    '''
    read cached data from file
    '''
    logging.debug('Started')
    count_files, count_suffixes, count_magics = get_count_files(data)
    logging.info('Writing cached data in pickle file %s with %s suffixes and %s magics in %s files',
                  cache_data_file, count_suffixes, count_magics, count_files)
    if len(data) == 0:
        logging.warning('No data available to write in cache file')
        return

    with open(cache_data_file, 'wb') as file_out:
        pickle.dump(data, file_out)
    cache_data_file.chmod(0o600)
    logging.debug('Ended')

def is_known_exception_file(exceptions_data: list, file_name: Path, file_magic: str) -> bool:
    '''
    check if file is a known exception
    '''
    logging.debug('Started')
    file_name_str = file_name.as_posix()
    for exception_file, exception_magic in exceptions_data:
        if exception_file != file_name_str:
            continue
        if exception_magic == file_magic:
            logging.info('Found correct exception for file %s with magic "%s"', file_name_str, file_magic)
        else:
            logging.error('Found incorrect exception for file %s  "%s" != "%s"', file_name_str, exception_magic, file_magic)
        return True

    logging.debug('Ended')
    return False

def get_files_from_disk(directory: Path, max_age: int, exceptions_file: Path) -> dict:
    '''
    find files from disk in directory and get some meta information
    '''
    logging.debug('Started')

    files = subprocess.run(['find', directory, '-type' , 'f', '-mtime', f'-{max_age}'],
                            check=False, capture_output=True, encoding="utf-8").stdout.split('\n')
    logging.debug('found files: %s', files)

    recent_files: dict = {}
    exceptions_data = read_exceptions_file(exceptions_file)

    for file in files:
        path_file = Path(file)
        if not path_file.is_file():
            continue
        file_magic = magic_file_type(path_file)
        file_suffix = path_file.suffix.lstrip('.').lower()

        if is_known_exception_file(exceptions_data=exceptions_data, file_name=path_file, file_magic=file_magic):
            logging.info('Removing exception %s from list', path_file)
            exceptions_data = [exception_data for exception_data in exceptions_data if exception_data[0] != path_file.as_posix()]
            continue

        path_file_data = FileDataTupple(path=path_file, name=path_file.name, magic_string=file_magic,
                                        suffix=file_suffix, mtime=path_file.stat().st_mtime)
        recent_files.setdefault(file_suffix, {})
        recent_files[file_suffix].setdefault(file_magic, [])
        recent_files[file_suffix][file_magic].append(path_file_data)

    for exception_file, exception_magic in exceptions_data:
        logging.error('Unused exception in file: %s with magic "%s"', exception_file, exception_magic)

    logging.debug('Ended')
    return recent_files

def get_files(directory: Path, max_age: int, cache_data: bool, exceptions_file: Path) -> dict:
    '''
    find files in directory and get some meta information
    '''
    logging.debug('Started')
    cache_data_file = get_cache_filename(directory=directory, max_age=max_age, exceptions_file=exceptions_file)
    if cache_data  and  cache_data_file.is_file()  and  cache_data_file.stat().st_mtime > time.time() - 3600:
        logging.debug('Ended')
        return read_cached_data(cache_data_file=cache_data_file)

    recent_files = get_files_from_disk(directory=directory, max_age=max_age, exceptions_file=exceptions_file)

    if cache_data:
        write_cached_data(cache_data_file=cache_data_file, data=recent_files)
    else:
        count_files, count_suffixes, count_magics = get_count_files(recent_files)
        logging.info('Found %s suffixes and %s magics in %s files', count_suffixes, count_magics, count_files)

    logging.debug('Ended')
    return recent_files

def magic_file_type(file: Path) -> str:
    '''
    get file magic for file and simplify this
    '''
    file_magic = magic.from_file(file)
    file_magic = re.sub(r',.*', '', file_magic)                   # remove part after comma
    file_magic = re.sub(r'\s*\(.*', '', file_magic)               # remove part after (
    file_magic = re.sub(r'\s+\-\s+.*', '', file_magic)            # remove part after " - "
    file_magic = re.sub(r'\d+\.\d+\.\d+', 'X.Y.Z', file_magic)    # change 1.2.3 to X.Y.Z
    file_magic = re.sub(r'\d+\.\d+', 'X.Y', file_magic)           # change 1.2 to X.Y
    file_magic = re.sub(r'\s*\[.*', '', file_magic)               # remove part after [
    file_magic = re.sub(r'\s*\".*', '', file_magic)               # remove part after "
    file_magic = re.sub(r'Version \d+', 'Version N', file_magic)  # change Version 1 to Version N

    return file_magic.strip()

def read_config_file(file: Path) -> dict:
    '''
    read config file
    '''

    logging.debug('Reading config file %s', file)
    if not Path(file).is_file():
        logging.error('config file %s does not exist', file)
        sys.exit(1)

    with open(file, encoding='utf-8') as config_file:
        config = json.load(config_file)

    config.setdefault('suffixes', {})

    return config

def read_exceptions_file(file: Path) -> list:
    '''
    read exceptions file
    '''

    logging.debug('Reading exceptions file %s', file)
    if file is None:
        return []

    if not Path(file).is_file():
        logging.error('exceptions file %s does not exist', file)
        sys.exit(1)

    with open(file, encoding='utf-8') as exceptions_file:
        exceptions = json.load(exceptions_file)

    return exceptions

def generate_config_file(config_file: Path, suffix_statistics: list, suffix_magic_statistics: list) -> None:
    '''
    Generate config file from parsed dataset
    '''
    logging.debug('Started')
    config: Dict[str, Any] = {}

    config['suffixes'] = {}
    #   "a": {
    #       "expected-result": ["ASCII text", "X data" ],
    #   },

    for suffix_statistic in suffix_statistics:
        count_comment = 0
        expected_results = []
        config['suffixes'][suffix_statistic.suffix] = {}
        suffix_config = config['suffixes'][suffix_statistic.suffix]

        for suffix_magic_statistic in suffix_magic_statistics:
            if suffix_magic_statistic.suffix != suffix_statistic.suffix:
                continue
            count_comment += 1
            comment_name = f'comment-{suffix_statistic.suffix}-{count_comment:02d}'
            date_range = f'{unix_time_to_day_string(suffix_magic_statistic.oldest)}-{unix_time_to_day_string(suffix_magic_statistic.newest)}'
            suffix_config[comment_name] = f'#={suffix_magic_statistic.count:05d}  {date_range} - {suffix_magic_statistic.magic_string}'
            expected_results.append(suffix_magic_statistic.magic_string)

        comment_name = f'comment-{suffix_statistic.suffix}-{0:02d}'
        date_range = f'{unix_time_to_day_string(suffix_statistic.oldest)}-{unix_time_to_day_string(suffix_statistic.newest)}'
        suffix_config[comment_name] = f'#={suffix_statistic.count:05d}  {date_range} - ALL MAGICS'
        suffix_config['expected-result'] = expected_results

    with Path(config_file).open("w", encoding="UTF-8") as target:
        json.dump(config, target, sort_keys=True, indent=4)

    logging.info('Config file saved in file %s now', config_file)
    logging.debug('Ended')

def write_exceptions_file(exceptions_file: Path, exceptions_data: list) -> None:
    '''
    Generate exceptions file from parsed dataset
    '''
    logging.debug('Started')

    with Path(exceptions_file).open("w", encoding="UTF-8") as target:
        json.dump(exceptions_data, target, sort_keys=True, indent=4)

    logging.info('Exceptions file saved in file %s now', exceptions_file)
    logging.debug('Ended')

def get_suffix_magic_stats( suffix: str, magic_string: str, suffix_config: dict,
        recent_files_suffix: dict, report_errors: bool) -> tuple[SuffixMagicTupple, list[list[Any]]]:
    '''
    Get suffix and suffix/magic stats
    '''
    logging.debug('Started')
    newest_suffix_magic_file = 0
    oldest_suffix_magic_file = int(time.time())
    suffix_magic_exceptions_data = []
    count_error_files = 0

    is_known_suffix_magic = magic_string in suffix_config.get('expected-result', [])
    magic_files = recent_files_suffix[magic_string]

    for magic_file in magic_files:
        newest_suffix_magic_file = max(magic_file.mtime, newest_suffix_magic_file)
        oldest_suffix_magic_file = min(magic_file.mtime, oldest_suffix_magic_file)
        if not is_known_suffix_magic:
            count_error_files += 1
            suffix_magic_exceptions_data.append([magic_file.path.as_posix(), magic_string])
            if report_errors:
                logging.error('File %s has unknown magic "%s"', magic_file.name, magic_string)

    suffix_magic_statistic = SuffixMagicTupple(suffix=suffix, magic_string=magic_string, count=len(magic_files),
                                               oldest=oldest_suffix_magic_file, newest=newest_suffix_magic_file,
                                               is_known_suffix_magic=is_known_suffix_magic)
    logging.debug('[%s] [%s] magic statistic: %s', suffix, magic_string, suffix_magic_statistic)

    return suffix_magic_statistic, suffix_magic_exceptions_data

def unix_time_to_day_string(time_in_seconds: int) -> str:
    '''
    Unix seconds to day string
    '''
    return time.strftime('%Y%m%d', time.localtime(time_in_seconds))

def get_oldest_suffix_file(suffix_magic_statistics: list) -> int:
    '''
    get the oldest suffix file from the suffix/magic statistics
    '''
    oldest_suffix_file = int(time.time())
    for suffix_magic_statistic in suffix_magic_statistics:
        oldest_suffix_file = min(oldest_suffix_file, suffix_magic_statistic.oldest)
    return oldest_suffix_file

def get_newest_suffix_file(suffix_magic_statistics: list) -> int:
    '''
    get the newest suffix file from the suffix/magic statistics
    '''
    newest_suffix_file = 0
    for suffix_magic_statistic in suffix_magic_statistics:
        newest_suffix_file = max(newest_suffix_file, suffix_magic_statistic.oldest)
    return newest_suffix_file

def get_suffix_stats(suffix: str, suffixes_config: dict, recent_files_suffix: dict,
                     report_errors: bool) -> tuple[SuffixTupple, list[SuffixMagicTupple], list[Any]]:
    '''
    Get suffix and suffix/magic stats
    '''
    logging.debug('Started')
    logging.debug('Suffix=%s', suffix)

    count_error_files = count_suffix_files = 0
    suffix_magic_statistics = []
    new_exceptions_data = []

    for magic_string in recent_files_suffix:
        suffix_magic_statistic, suffix_magic_exception_data = get_suffix_magic_stats(
            suffix=suffix, magic_string=magic_string, suffix_config=suffixes_config.get(suffix, {}),
            recent_files_suffix=recent_files_suffix, report_errors=report_errors)
        new_exceptions_data.extend(suffix_magic_exception_data)

        count_suffix_files += suffix_magic_statistic.count
        if not suffix_magic_statistic.is_known_suffix_magic:
            count_error_files += suffix_magic_statistic.count

        logging.debug('[%s] [%s] magic statistic: %s', suffix, magic_string, suffix_magic_statistic)
        suffix_magic_statistics.append(suffix_magic_statistic)

    suffix_statistic = SuffixTupple(suffix=suffix,
                                    count=count_suffix_files,
                                    errors=count_error_files,
                                    oldest=get_oldest_suffix_file(suffix_magic_statistics),
                                    newest=get_newest_suffix_file(suffix_magic_statistics),
                                    is_known_suffix=bool(suffixes_config)
                                   )
    logging.debug('[%s] [%s] suffix statistic: %s', suffix, "ALL", suffix_statistic)
    logging.debug('Ended')

    return suffix_statistic, suffix_magic_statistics, new_exceptions_data

def get_recent_file_stats(config: dict, recent_files: dict, report_errors: bool,
                          generate_exceptions_file: Path) -> tuple[list, list]:
    '''
    Get suffix and suffix/magic stats
    '''
    logging.debug('Started')
    new_exceptions_data = []
    suffix_statistics = []
    suffix_magic_statistics = []
    suffixes_config = config.get('suffixes', {})

    for suffix in recent_files:
        logging.debug('Suffix=%s', suffix)
        suffix_statistic, suffix_magic_statistic, new_suffix_exceptions_data = get_suffix_stats(
            suffix=suffix, suffixes_config=suffixes_config, recent_files_suffix=recent_files[suffix],
            report_errors=report_errors)
        new_exceptions_data.extend(new_suffix_exceptions_data)

        logging.debug('[%s] [%s] suffix statistic: %s', suffix, "ALL", suffix_statistic)
        suffix_statistics.append(suffix_statistic)
        suffix_magic_statistics.extend(suffix_magic_statistic)

    if generate_exceptions_file:
        write_exceptions_file(exceptions_file=generate_exceptions_file, exceptions_data=new_exceptions_data)

    logging.debug('Ended')
    return sorted(suffix_statistics), sorted(suffix_magic_statistics)

def generate_summary_report(suffix_statistics: dict) -> None:
    '''
    Generate summary report
    '''
    logging.debug('Started')
    count_files = count_skipped_files = count_correct_files = count_error_files = count_unknown_suffix_files = 0
    for suffix_statistic in suffix_statistics:
        count_files += suffix_statistic.count
        if suffix_statistic.is_known_suffix:
            count_error_files += suffix_statistic.errors
        else:
            count_unknown_suffix_files += suffix_statistic.errors
    count_correct_files = count_files - count_error_files - count_unknown_suffix_files

    print()
    print(f'count files               : {count_files:6d}')
    print(f'count skipped files       : {count_skipped_files:6d}')
    print(f'count correct files       : {count_correct_files:6d}')
    print(f'count error files         : {count_error_files:6d}')
    print(f'count unknown suffix files: {count_unknown_suffix_files:6d}')

    print()
    for suffix_statistic in suffix_statistics:
        if suffix_statistic.errors == 0  and  suffix_statistic.is_known_suffix:
            continue
        correct_files = suffix_statistic.count - suffix_statistic.errors
        print(f'{suffix_statistic.suffix:<20s}: {unix_time_to_day_string(suffix_statistic.oldest)}-{unix_time_to_day_string(suffix_statistic.newest)}  ', end='')
        print(f'#={suffix_statistic.count:6d}  C={correct_files:6d}  E={suffix_statistic.errors:6d}')
    logging.debug('Ended')

def main():
    '''
    main
    '''

    args = get_arguments()

    # Configure the logging
    numeric_level = getattr(logging, args.log.upper(), None)
    logging.basicConfig(format='%(asctime)s [%(levelname)s] [%(funcName)s]   %(message)s',
                        datefmt="%Y%m%d-%H%M%S", level=numeric_level, stream=sys.stdout)

    # Some initialization
    config = {}
    if not args.generate_config_file is not None:
        config = read_config_file(args.config_file)

    if args.generate_config_file is not None  and  Path(args.generate_config_file).is_file():
        logging.error('Cannot generate config file %s, as file already exists', args.generate_config_file)
        sys.exit(1)

    if args.generate_exceptions_file is not None:
        args.exceptions_file = None

    recent_files = get_files(directory=args.directory, max_age=args.max_age,
                             cache_data=args.cache_data, exceptions_file=args.exceptions_file)
    suffix_statistics, suffix_magic_statistics = get_recent_file_stats(
        config=config,
        recent_files=recent_files,
        report_errors=True,
        generate_exceptions_file=args.generate_exceptions_file
       )

    if args.generate_config_file is not None:
        generate_config_file(config_file=args.generate_config_file, suffix_statistics=suffix_statistics,
                             suffix_magic_statistics=suffix_magic_statistics)
    if args.summary:
        generate_summary_report(suffix_statistics)

#  Main part here
#---------------------------------------------------------------------------
if __name__ == "__main__":
    main()

else:
    # Test several functions
    pass
