#!/usr/bin/env python3

#  ┌────────────────────────────────────────────────────────────────────────────────┐
#  │                                                                                │
#  │ ███████╗██╗  ██╗ █████╗ ███╗   ███╗██╗██████╗         ███████╗███████╗███████╗ │
#  │ ██╔════╝██║  ██║██╔══██╗████╗ ████║██║██╔══██╗        ██╔════╝██╔════╝██╔════╝ │
#  │ ███████╗███████║███████║██╔████╔██║██║██████╔╝        ███████╗███████╗███████╗ │
#  │ ╚════██║██╔══██║██╔══██║██║╚██╔╝██║██║██╔══██╗        ╚════██║╚════██║╚════██║ │
#  │ ███████║██║  ██║██║  ██║██║ ╚═╝ ██║██║██║  ██║███████╗███████║███████║███████║ │
#  │ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝ │
#  └────────────────────────────────────────────────────────────────────────────────┘

import argparse
import itertools
import logging
import qrcode
import random
import re
import sympy
import sys


from PIL import Image
from pathlib import Path

try:
    from pyzbar.pyzbar import decode

    HAS_PYZBAR = True
except:

    def decode(image) -> list:
        return [image]

    HAS_PYZBAR = False


__author__ = 'MCDM'
__copyright__ = 'Copyright 2025'
__license__ = 'MIT'
__version__ = '2025-09.05'


class CustomFormatter(logging.Formatter):
    """
    logging
    """

    grey = '\x1b[38;2;152;152;152m'
    grey_background = grey.replace('38', '48')
    white = '\x1b[38;2;224;242;224m'
    yellow = '\x1b[33;20m'
    red = '\x1b[31;20m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'
    msg_format = '%(message)s'

    FORMATS = {
        logging.DEBUG: grey + msg_format + reset,
        logging.INFO: white + msg_format + reset,
        logging.WARNING: yellow + msg_format + reset,
        logging.ERROR: red + msg_format + reset,
        logging.CRITICAL: bold_red + msg_format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, '%H:%M:%S')
        return formatter.format(record)


def get_arguments() -> argparse.Namespace:
    """
    get commandline arguments
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Shamir Secret Sharing arguments', epilog='© MCDM, 2025')
    choices = ['debug', 'info', 'warning', 'error', 'critical']
    parser.add_argument('--log-level', help="Set log level (default '%(default)s')", choices=choices, default='debug')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)

    sub = parser.add_subparsers(dest='cmd', required=True)

    epilog = """

Example call:
-------------
   $ %(prog)s  --secret welcome  --threshold 2  --shares 3
   Generated shares:
      E9EEC0-SP128-T2-prime-340282366920938463463374607431768196007
      E9EEC0-SP128-T2-1-3083D425925C95B124751355B0AF99D2
      E9EEC0-SP128-T2-2-6107A84B24B92B624872C13EFDEFC63F
      E9EEC0-SP128-T2-3-918B7C70B715C1136C706F284B2FF2AC

   Testing all share combinations
      All 3 combinations successfully reconstructed the secret.

   Prime number used:
      decimal: ( 16 bytes) 340282366920938463463374607431768196007
      hex    : ( 32 bytes) 0xffffffffffffffffffffffffffffc3a7
      bitsize:      128


Structure share:
---------------- 
An example share looks like: E9EEC0-SP128-T2-3-3083D425925C95B124751355B0AF99D2

This has the following elements:
. E9EEC0: this is a random number that is used to identify all shares belonging to each other.
          So for all shares this number MUST be te same!
. SP128 : this is refering to a safe prime number with 128 bits. You can find more info here:
          https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes
. T2    : this is refering to the number of different shares NEEDED to calculate the secret
. 3     : this is the share with x-value=3
. HEX   : the y-value for this share in HEX is: 3083D425925C95B124751355B0AF99D2

        """
    p_split = sub.add_parser('split', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
    unique_name = f'{random.randrange(2**24):X}'
    p_split.add_argument(
        '-n',
        '--unique-name',
        type=str,
        help="The pattern used for filenames when QR files are generated (default '%(default)s')",
        default=unique_name,
        metavar='IDX',
    )
    p_split.add_argument('-S', '--secret', metavar='STRING')
    p_split.add_argument('--secret-file', help='file with the secret', metavar='FILE')
    p_split.add_argument('--keyboard-secret', help='read the secret from the keyboard', action='store_true')
    p_split.add_argument('-t', '--threshold', type=int, required=True, metavar='INT')
    p_split.add_argument('-s', '--shares', type=int, required=True, metavar='INT')
    p_split.add_argument('--prime', type=int, help='prime number used in algorithm (no default)', metavar='INT')
    p_split.add_argument('--strength-level', type=int, help="minimum prime length in bits (default '%(default)s')", default=127, metavar='INT')
    p_split.add_argument('--use-small-primes', help='Use the smallest possible prime for polynome', action='store_true')
    p_split.add_argument('--qr', help='Generate QR-code files', action='store_true')
    p_split.add_argument('--strong', help='Strongest possible security', action='store_true')
    p_split.add_argument('--showpoly', help='Show the polynome coëfficiënts', action='store_true')

    epilog = """

Example call:
-------------
   $ %(prog)s  --share E9EEC0-SP128-T2-2-6107A84B24B92B624872C13EFDEFC63F  --share E9EEC0-SP128-T2-3-918B7C70B715C1136C706F284B2FF2AC

   Prime number used:
      decimal: 340282366920938463463374607431768196007
      hex    : 0xffffffffffffffffffffffffffffc3a7
      bitsize: 128

   Secret (between ||):
      |welcome|

So the secret is found here ("welcome").
It also shows the prime numbers used for the calculations. This SHOULD be the same as used when generating the shares.
        """
    p_recover = sub.add_parser('recover', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
    p_recover.add_argument('-s', '--share', action='append', help='share data, use option multiple times', metavar='STRING')
    p_recover.add_argument('-q', '--qr-share-files', action='append', help='QR-code file with share, use option multiple times', metavar='FILE')
    p_recover.add_argument('-Q', '--qr-prime-file', help='QR-code file with prime number', metavar='FILE')
    p_recover.add_argument('--prime', type=int, help='prime number used in algorithm (no default)', metavar='INT')
    p_recover.add_argument('--secret-file', help='file to store secret', metavar='FILE')

    p_primes = sub.add_parser('primes', description='Show the used safe prime numbers')
    p_primes.add_argument('--list', help='List prime numbers', action='store_true')
    p_primes.add_argument('--decimal-format', help='Show primes in decimal format instead of hex format', action='store_true')

    return parser.parse_args()


def get_safe_prime_numbers() -> list:
    """
    A safe prime is a prime of the form 2p + 1, where p is also a prime (Sophie Germain prime).

    Returns:
        int: A safe prime number list
    """

    safe_prime_numbers = [
        1187,
        262643,
        67109543,
        17179869263,
        4398046512059,
        1125899906846567,
        288230376151720907,
        73786976294838218759,
        4835703278458516698825743,
        316912650057057350374175803367,
        20769187434139310514121985316894863,
        1361129467683753853853498429727072850727,
        5846006549323611672814739330865132078623730177143,
        25108406941546723055343157692830665664409421777856138053787,
        107839786668602559178668060348078522694548577690162289924414441006387,
        463168356949264781694283940034751631413079938662562256157830336031652518612647,
    ]

    for safe_prime_number in safe_prime_numbers:
        if not sympy.isprime(n=safe_prime_number):
            logger.critical('Error! prime number %s is not really a prime!', safe_prime_number)
            sys.exit(1)

    return sorted(safe_prime_numbers)


def extract_integer_from_string(number) -> int:
    # Find all sequences of digits at the end of the string
    match = re.search(r'(\d+)$', number)
    if match:
        return int(match.group(1))

    logger.critical('Cannot find number information in string', number)
    sys.exit(1)


def get_large_enough_prime(batch: list[int], nr_bits: int, primes: list[int]) -> int:
    """Returns a prime number that is greater all the numbers in the batch."""
    max_batch = max(batch + [0])
    max_bit_length_batch = (max_batch.bit_length() // 8 + 0) * 8

    for prime in primes:
        if prime.bit_length() < nr_bits:
            continue
        if prime.bit_length() > max_bit_length_batch:
            return prime

    logger.critical(f'Error! Cannot find prime with bit length of at least {nr_bits} bits!')
    sys.exit(1)


def _to_int(secret: bytes) -> int:
    return int.from_bytes(secret, byteorder='big')


def _from_int(i: int) -> bytes:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder='big')


def _eval_poly(coeffs: list[int], x: int, prime: int) -> int:
    result = 0
    power = 1
    for a in coeffs:
        result = (result + a * power) % prime
        power = (power * x) % prime
    return result


def _lagrange_interpolate(x: int, x_s: list[int], y_s: list[int], prime: int) -> int:
    total = 0
    k = len(x_s)
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        num, den = 1, 1
        for j in range(k):
            if i == j:
                continue
            xj = x_s[j]
            num = (num * (x - xj)) % prime
            den = (den * (xi - xj)) % prime
        inv_den = pow(den, -1, prime)
        total = (total + yi * num * inv_den) % prime
    return total


def make_shares(secret: bytes, threshold: int, num_shares: int, prime: int) -> tuple[list[tuple[int, int]], list[int], int]:
    if num_shares > prime:
        logger.error('prime (%s) is smaller than number of shares (%s)', prime, num_shares)
        sys.exit(1)
    secret_int = _to_int(secret)
    coeffs = [secret_int] + [random.randrange(start=prime // 128, stop=prime) for _ in range(threshold - 1)]
    shares = [(x, _eval_poly(coeffs, x, prime)) for x in range(1, num_shares + 1)]
    return shares, coeffs, prime


def recover_secret(shares: list[tuple[str, int, int, int, int]], primes: list[int]) -> tuple[int, bytes]:
    idx, nr_bits, threshold, x_s, y_s = zip(*shares)
    if len(set(idx)) != 1:
        logger.critical('Error! set of shares do not belong to each other (IDX wrong)')
        sys.exit(1)
    if len(set(nr_bits)) != 1:
        logger.critical('Error! set of shares do not belong to each other (#bits wrong)')
        sys.exit(1)
    if len(set(threshold)) != 1:
        logger.critical('Error! set of shares do not belong to each other (threshold wrong)')
        sys.exit(1)

    if len(shares) < threshold[0]:
        logger.critical('For this secret I need %s shares, but I only got %s shares', threshold[0], len(shares))
        sys.exit(1)

    prime = get_large_enough_prime(batch=[], nr_bits=nr_bits[0], primes=primes)
    secret_int = _lagrange_interpolate(x=0, x_s=list(x_s), y_s=list(y_s), prime=prime)
    return prime, _from_int(secret_int)


def _share_to_text(share: tuple[int, int], nr_bits, unique_name: str, threshold: int, number_format: str = 'hex') -> str:
    x, y = share
    partial_string = f'{unique_name}-SP{nr_bits}-T{threshold}-{x}'
    if number_format == 'decimal':
        return f'{' ' * len(partial_string)} {y:<10} DECIMAL:  NEVER USE THIS FOR RECOVERY, IT WILL NOT WORK'
    elif number_format == 'hex':
        return f'{partial_string}-{y:X}'

    logger.critical('Unknown number format used in _share_to_text')
    sys.exit(1)


def _text_to_share(text: str) -> tuple[str, int, int, int, int]:
    idx, nr_bits, threshold, x_str, y_hex = text.split('-', 4)
    return idx, extract_integer_from_string(number=nr_bits), extract_integer_from_string(number=threshold), int(x_str), int(y_hex, 16)


def save_qr(data: str, filename: str, is_prime: bool = False) -> None:
    img = qrcode.make(data)
    img.save(filename)
    if is_prime:
        logger.debug('   Saving prime number to QR-code file %s', filename)
    else:
        logger.debug('     Saving share to QR-code file %s', filename)


def read_qr(filename: str) -> str:
    if not HAS_PYZBAR:
        logger.critical('Reading QR code file is not available')
        logger.info('Alternative: read the QR code with a mobile and use the "--share" option instead')
        sys.exit(1)
    img = Image.open(filename)
    decoded_objs = decode(img)
    results = [obj.data.decode('utf-8') for obj in decoded_objs]
    return results[0]


def get_hex_size(number: int) -> str:
    return f'{len(hex(number)) - 2:3d}'


def get_integer_size(number: int) -> str:
    return f'{(number.bit_length() + 7) // 8:3d}'


def test_generated_shares(secret_bytes: bytes, shares: list[tuple[str, int, int, int, int]], threshold: int, prime: int) -> None:
    """
    Test all possible combinations of shares for reconstruction.
    """
    logger.warning('\nTesting all share combinations')

    all_combinations_are_ok = True
    count_combinations = 0
    for subset in itertools.combinations(shares, threshold):
        count_combinations += 1
        _, reconstructed = recover_secret(shares=list(subset), primes=[prime])
        if reconstructed != secret_bytes:
            all_combinations_are_ok = False
            logger.critical('Combination %s: Failed', subset)

    if all_combinations_are_ok:
        logger.info('   All %s combinations successfully reconstructed the secret.', count_combinations)
    else:
        logger.error('   ERROR: Not all valid combinations successfully reconstructed the secret.')


def mode_split(secret_bytes: bytes, threshold: int, num_shares: int, prime: int, qr: bool, unique_name: str, showpoly: bool) -> None:
    shares, coeffs, prime = make_shares(secret=secret_bytes, threshold=threshold, num_shares=num_shares, prime=prime)
    number_format = 'decimal' if prime.bit_length() < 35 else 'hex'
    logger.warning('Generated shares:')
    prime_number_id = f'{unique_name}-SP{prime.bit_length()}-T{threshold}-prime'
    print(f'   {prime_number_id}-{prime}')  # print used here, as we donot want any formatting characters here!
    if qr:
        save_qr(data=str(prime), filename=f'QR-shamir_sss-{prime_number_id}.png', is_prime=True)
    hex_shares = []
    for idx, s in enumerate(shares):
        share_text = _share_to_text(share=s, unique_name=unique_name, nr_bits=prime.bit_length(), threshold=threshold, number_format='hex')
        hex_shares.append(_text_to_share(text=share_text))
        print(f'   {share_text}')  # print used here, as we donot want any formatting characters here!

        if qr:
            save_qr(data=share_text, filename=f'QR-shamir_sss-{unique_name}-SP{prime.bit_length()}-T{threshold}-{idx+1}.png')

        if number_format == 'decimal':
            share_text_decimal = _share_to_text(share=s, unique_name='', nr_bits=prime.bit_length(), threshold=threshold, number_format='decimal')
            logger.debug('   %s', share_text_decimal)

    test_generated_shares(secret_bytes=secret_bytes, shares=hex_shares, threshold=threshold, prime=prime)
    logger.warning('\nPrime number used:')
    logger.info('   decimal: (%s bytes) %s', get_integer_size(prime), prime)
    logger.info('   hex    : (%s bytes) %s', get_hex_size(prime), hex(prime))
    logger.info('   bitsize:      %s', prime.bit_length())
    if showpoly:
        logger.warning('\nPolynome coëfficiënts (const term first):')
        for i, c in enumerate(coeffs):
            logger.info('   a%s =\t(%s bytes)  %s', i, get_hex_size(c), hex(c))
            logger.debug('   \t%s', c)


def mode_recover(shares: list[str], qr_share_files: list[str], qr_prime_file: str, primes: list[int], secret_file: str) -> None:
    found_shares = []
    if shares:
        found_shares.extend([_text_to_share(s) for s in shares])
    if qr_share_files:
        for qrfile in qr_share_files:
            text = read_qr(qrfile)
            found_shares.append(_text_to_share(text))
    if qr_prime_file:
        prime = read_qr(qr_prime_file)
        primes = [int(prime)]

    if not found_shares:
        logger.critical('No shares provided, please use --share option')
        sys.exit(1)
    prime, secret_bytes = recover_secret(shares=found_shares, primes=primes)
    logger.warning('\nPrime number used:')
    logger.info('   decimal: %s', prime)
    logger.info('   hex    : %s', hex(prime))
    logger.info('   bitsize: %s', prime.bit_length())
    if secret_file:
        with open(secret_file, 'wb') as f:
            logger.warning('Secret written to file %s', secret_file)
            f.write(secret_bytes)
    else:
        try:
            logger.warning('\nSecret (between ||):')
            print(f'   |{secret_bytes.decode()}|')  # print used here, as we donot want any formatting characters here!
        except UnicodeDecodeError:
            logger.critical('Cannot decode secret properly, decoded to  |%s|', secret_bytes)


def main() -> None:
    args = get_arguments()

    # create logger with 'spam_application'
    logger = logging.getLogger(Path(__file__).stem)
    logger.setLevel(level=args.log_level.upper())

    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)

    standard_primes = get_safe_prime_numbers()  # support secrets up to 160 characters

    #  ┌──────────────────────────────────────┐
    #  │                                      │
    #  │ ███████╗██████╗ ██╗     ██╗████████╗ │
    #  │ ██╔════╝██╔══██╗██║     ██║╚══██╔══╝ │
    #  │ ███████╗██████╔╝██║     ██║   ██║    │
    #  │ ╚════██║██╔═══╝ ██║     ██║   ██║    │
    #  │ ███████║██║     ███████╗██║   ██║    │
    #  │ ╚══════╝╚═╝     ╚══════╝╚═╝   ╚═╝    │
    #  └──────────────────────────────────────┘
    if args.cmd == 'split':
        if args.strength_level < 127:
            logger.critical('Security is not SAFE as a too small prime could be used for security reasons')
        if args.strong:
            standard_primes = [standard_primes[-1]]

        if args.keyboard_secret:
            secret_string = input('Please type secret here:  ')
            secret_bytes = secret_string.encode()
        elif args.secret:
            secret_bytes = args.secret.encode()
        elif args.secret_file:
            with open(args.secret_file, 'rb') as f:
                secret_bytes = f.read()
        else:
            logger.critical('Please use --keyboard-secret, --secret or --secret-file option')
            sys.exit(1)
        prime = get_large_enough_prime(batch=[_to_int(secret_bytes)], nr_bits=args.strength_level, primes=standard_primes)
        if args.prime:
            prime = args.prime
            if not sympy.isprime(n=prime):
                logger.critical('given prime (%s) is not a prime', prime)
                sys.exit(1)
        if _to_int(secret_bytes) > prime:
            logger.critical(
                'Used prime number (%s) is too small for this secret (%s), should be at least: %s', prime, secret_bytes, _to_int(secret=secret_bytes)
            )
            sys.exit(1)
        mode_split(
            secret_bytes=secret_bytes,
            threshold=args.threshold,
            num_shares=args.shares,
            unique_name=args.unique_name,
            prime=prime,
            qr=args.qr,
            showpoly=args.showpoly,
        )

    #  ┌────────────────────────────────────────────────────────────┐
    #  │                                                            │
    #  │ ██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗  │
    #  │ ██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗ │
    #  │ ██████╔╝█████╗  ██║     ██║   ██║██║   ██║█████╗  ██████╔╝ │
    #  │ ██╔══██╗██╔══╝  ██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗ │
    #  │ ██║  ██║███████╗╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║ │
    #  │ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝ │
    #  └────────────────────────────────────────────────────────────┘
    elif args.cmd == 'recover':
        if args.prime:
            standard_primes = [args.prime]
        mode_recover(
            shares=args.share, qr_share_files=args.qr_share_files, qr_prime_file=args.qr_prime_file, primes=standard_primes, secret_file=args.secret_file
        )

    #  ┌────────────────────────────────────────────────┐
    #  │                                                │
    #  │ ██████╗ ██████╗ ██╗███╗   ███╗███████╗███████╗ │
    #  │ ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝██╔════╝ │
    #  │ ██████╔╝██████╔╝██║██╔████╔██║█████╗  ███████╗ │
    #  │ ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝  ╚════██║ │
    #  │ ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗███████║ │
    #  │ ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ │
    #  └────────────────────────────────────────────────┘
    elif args.cmd == 'primes':
        if args.list:
            logger.warning('Available primes:')
            for standard_prime in standard_primes:
                if args.decimal_format:
                    logger.info(f' {standard_prime.bit_length():4d} -> {standard_prime}')
                else:
                    logger.info(f' {standard_prime.bit_length():4d} -> 0x{standard_prime:X}')


if __name__ == '__main__':
    logger = logging.getLogger(Path(__file__).stem)
    main()
