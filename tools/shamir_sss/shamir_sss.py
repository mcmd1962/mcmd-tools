#!/usr/bin/env python3
"""shamir_sss.py"""

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
import string
import sympy
import sys


from PIL import Image
from pathlib import Path
from collections.abc import Generator

try:
    from pyzbar.pyzbar import decode

    HAS_PYZBAR = True
except:

    def decode(image) -> list:
        return [image]

    HAS_PYZBAR = False


__author__ = 'MCMD'
__copyright__ = 'Copyright 2025'
__license__ = 'MIT'
__version__ = '2025-10.06'


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
    parser = argparse.ArgumentParser(description='Shamir Secret Sharing arguments', epilog='© MCMD, 2025')
    choices = ['debug', 'info', 'warning', 'error', 'critical']
    parser.add_argument('--log-level', help="Set log level (default '%(default)s')", choices=choices, default='debug')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)

    sub = parser.add_subparsers(dest='cmd', required=True)

    epilog = """

Example call:
-------------
   $ %(prog)s  --secret welcome  --threshold 2  --shares 3
   Generated shares:
      ID.DA1D17-SP256-T2-prime-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF72EF
      ID.DA1D17-SP256-T2-800000006F3-8F3E2E28038B271B5AE37E6243A1F550EC1151FBF89DD0D04B87664BE871559A
      ID.DA1D17-SP256-T2-8000000076B-B8F6E3735691F95464D998D091EE22831CC463993D6548311279E1356C064D25
      ID.DA1D17-SP256-T2-80000000C7B-7B8E896DA40ED7BC6A084FDE45F1A43AC45255088A9C5179771B10A8F91D0BF1

   Testing all share combinations
      All 3 combinations successfully reconstructed the secret.
      Needed prime is not weak, need 256 bits

   Prime number used:
      hex    : FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF72EF
      decimal: 115792089237316195423570985008687907853269984665640564039457584007913129603823
      bitsize: 256


Structure share:
---------------- 
An example share looks like: ID.DA1D17-SP256-T2-800000006F3-8F3E2E28038B271B5AE37E6243A1F550EC1151FBF89DD0D04B87664BE871559A

This has the following elements:
. ID.DA1D17: this is a random number that is used to identify all shares belonging to each other.
             So for all shares this number MUST be te same!
. SP256    : this is refering to a safe prime number with 256 bits. You can find more info here:
             https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes
. T2       : this is refering to the number of different shares NEEDED to calculate the secret
. 800000006F3: this is the share with x-value=800000006F3 (HEX)
. HEX      : the y-value for this share is: 8F3E2E28038B271B5AE37E6243A1F550EC1151FBF89DD0D04B87664BE871559A (HEX)
. prime    : the prime number used needed for recovery purpose. The script will automatically select the correct one,
             but another implementation will probably select a different prime number, so in this case you will need
             this number. In this example the prime number in HEX is:
             FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF72EF


        """
    p_split = sub.add_parser('split', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
    unique_name = f'ID.{random.randrange(2**24):X}'
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
    p_split.add_argument('--PRIME', '-P', type=int, help='prime number used in algorithm, decimal type (no default)', metavar='INT')
    p_split.add_argument('--prime', '-p', type=str, help='prime number used in algorithm, string type for hex value (no default)', metavar='HEX-STR')
    p_split.add_argument('--strength-level', type=int, help="minimum prime length in bits (default '%(default)s')", default=255, metavar='INT')
    p_split.add_argument('--minimum-x-safe-prime', type=int, help="minimum safe prime for x-axis values (default '%(default)s')", default=2**43, metavar='INT')
    p_split.add_argument('--use-small-primes', help='Use the smallest possible prime for polynome', action='store_true')
    p_split.add_argument('--qr', help='Generate QR-code files', action='store_true')
    p_split.add_argument('--strong', help='Strongest possible security', action='store_true')
    p_split.add_argument('--showpoly', help='Show the polynome coëfficiënts', action='store_true')

    epilog = """

Example call:
-------------
   $ %(prog)s  --share ID.DA1D17-SP256-T2-800000006F3-8F3E2E28038B271B5AE37E6243A1F550EC1151FBF89DD0D04B87664BE871559A \\
                            --share ID.DA1D17-SP256-T2-8000000076B-B8F6E3735691F95464D998D091EE22831CC463993D6548311279E1356C064D25
   Prime number used:
      hex    : FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF72EF
      decimal: 115792089237316195423570985008687907853269984665640564039457584007913129603823
      bitsize: 256

   Secret (between ||):
      |welcome|

   So the secret is found here ("welcome").
   It also shows the prime numbers used for the calculations. This SHOULD be the same as used when generating the shares.
        """
    p_recover = sub.add_parser('recover', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
    p_recover.add_argument('-s', '--share', action='append', help='share data, use option multiple times', metavar='STRING')
    p_recover.add_argument('-q', '--qr-share-files', action='append', help='QR-code file with share, use option multiple times', metavar='FILE')
    p_recover.add_argument('-Q', '--qr-prime-file', help='QR-code file with prime number', metavar='FILE')
    p_recover.add_argument('--PRIME', '-P', type=int, help='prime number used in algorithm, decimal type (no default)', metavar='INT')
    p_recover.add_argument('--prime', '-p', type=str, help='prime number used in algorithm, string type for hex value (no default)', metavar='HEX-STR')
    p_recover.add_argument('--secret-file', help='file to store secret', metavar='FILE')

    p_primes = sub.add_parser('primes', description='Show the used safe prime numbers')
    p_primes.add_argument('--abbreviate', help='Show hex prime numbers in abbreviated format', action='store_true')
    p_primes.add_argument('--decimal-format', help='Show primes in decimal format instead of hex format', action='store_true')

    args = parser.parse_args()

    if args.cmd in ('recover', 'split') and args.prime and args.PRIME:
        logger.error('--prime and --PRIME are mutually exclusive')
        sys.exit(1)

    if args.cmd in ('recover', 'split') and args.prime:
        args.prime = int(args.prime, 16)
    elif args.cmd in ('recover', 'split') and args.PRIME:
        args.prime = args.PRIME

    return args


def get_safe_prime_numbers() -> list:
    """
    A safe prime is a prime of the form 2p + 1, where p is also a prime (Sophie Germain prime).

    Returns:
        int: A sorted safe prime number list
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

    for prime in primes:
        if prime.bit_length() < nr_bits:
            continue
        if prime.bit_length() > max_batch.bit_length():
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


def get_next_prime(prime: int) -> int:
    next_prime = sympy.nextprime(prime)
    if next_prime is None:
        logger.error('Failed to generate prime number')
        sys.exit(1)
    return next_prime


def get_next_safe_prime(prime: int) -> int:
    next_prime = prime
    if not sympy.isprime(prime):
        next_prime = get_next_prime(prime=prime)
    while True:
        safe_prime = 2 * next_prime + 1
        if sympy.isprime(safe_prime):
            return safe_prime
        next_prime = get_next_prime(prime=next_prime)


def prime_generator(minimum_prime: int) -> Generator[int]:
    step_bit = max(0, (minimum_prime.bit_length() // 8) * 4 - 1)
    step = 2**step_bit
    step_delta = 1
    next_prime = minimum_prime + step_delta * step
    while True:
        step_delta += 1
        safe_prime = get_next_safe_prime(prime=next_prime)
        next_prime = max(safe_prime // 2 + 3, minimum_prime + step_delta * step)

        yield safe_prime


def make_shares(secret: bytes, threshold: int, num_shares: int, prime: int, minimum_x_safe_prime: int) -> tuple[list[tuple[int, int]], list[int], int]:
    if num_shares > prime:
        logger.error('prime (%s) is smaller than number of shares (%s)', prime, num_shares)
        sys.exit(1)
    secret_int = _to_int(secret)
    coeffs = [secret_int] + [random.randrange(start=(prime - prime // 16), stop=prime) for _ in range(threshold - 1)]
    x_prime_generator = prime_generator(minimum_prime=minimum_x_safe_prime // 2)
    shares = [(x, _eval_poly(coeffs, x, prime)) for x in [next(x_prime_generator) for _ in range(num_shares)]]
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

    if len(set(shares)) < threshold[0]:
        logger.critical('For this secret I need %s shares, but I only got %s unique shares', threshold[0], len(set(shares)))
        sys.exit(1)

    if len(primes) == 0:
        logger.critical('No primes are available for the calculation')
        sys.exit(1)
    elif len(primes) == 1:
        prime = primes[0]
    else:
        prime = get_large_enough_prime(batch=[], nr_bits=nr_bits[0], primes=primes)
    secret_int = _lagrange_interpolate(x=0, x_s=list(x_s), y_s=list(y_s), prime=prime)
    return prime, _from_int(secret_int)


def _prime_to_text(prime: int, nr_bits, unique_name: str, threshold: int) -> str:
    partial_string = f'{unique_name}-SP{nr_bits}-T{threshold}-prime'
    return f'{partial_string}-{prime:X}'


def _share_to_text(share: tuple[int, int], nr_bits, unique_name: str, threshold: int, number_format: str = 'hex') -> str:
    x, y = share
    partial_string = f'{unique_name}-SP{nr_bits}-T{threshold}-{x:X}'
    if number_format == 'decimal':
        return f'{' ' * len(partial_string)} {y:<10} DECIMAL:  NEVER USE THIS FOR RECOVERY, IT WILL NOT WORK'
    elif number_format == 'hex':
        return f'{partial_string}-{y:X}'

    logger.critical('Unknown number format used in _share_to_text')
    sys.exit(1)


def _text_to_prime(text: str) -> int:
    return int(text.split('-')[-1], 16)


def _text_to_share(text: str) -> tuple[str, int, int, int, int]:
    idx, nr_bits, threshold, x_str, y_hex = text.split('-', 4)
    return idx, extract_integer_from_string(number=nr_bits), extract_integer_from_string(number=threshold), int(x_str, 16), int(y_hex, 16)


def save_qr(data: str, filename: str, is_prime: bool = False) -> None:
    img = qrcode.make(data)
    img.save(filename)
    if is_prime:
        logger.debug('     Saving prime to QR-code file %s', filename)
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


def are_generated_shares_ok(secret_bytes: bytes, shares: list[tuple[str, int, int, int, int]], threshold: int, prime: int) -> bool:
    """
    Test all possible combinations of shares for reconstruction.
    """
    logger.warning('\nTesting all share combinations')

    all_combinations_are_ok = True
    prime_is_weak = False
    count_combinations = 0
    weakest_needed_prime = prime
    problem_x = dict()
    for subset in itertools.combinations(shares, threshold):
        count_combinations += 1
        _, reconstructed = recover_secret(shares=list(subset), primes=[prime])
        if reconstructed != secret_bytes:
            all_combinations_are_ok = False
            logger.critical('Combination %s: Failed', subset)
        for weak_prime in get_safe_prime_numbers():
            _, reconstructed = recover_secret(shares=list(subset), primes=[weak_prime])
            if reconstructed == secret_bytes:
                if weak_prime <= weakest_needed_prime and weak_prime != prime:
                    for element in subset:
                        x = element[3]
                        if x not in problem_x:
                            problem_x[x] = 0

                        problem_x[x] += 1

                    prime_is_weak = True
                    weakest_needed_prime = weak_prime

    if all_combinations_are_ok:
        logger.info('   All %s combinations successfully reconstructed the secret.', count_combinations)
    else:
        logger.error('   ERROR: Not all valid combinations successfully reconstructed the secret.')

    if prime_is_weak:
        logger.error('   ERROR: vulnerable for weak prime attack with %s bits, needed %s bits', weakest_needed_prime.bit_length(), prime.bit_length())
        for x in sorted(problem_x):
            logger.warning('      x=%s  frequency problems=%s', f'{x:3X}', f'{problem_x[x]:2d}')
    else:
        logger.info('   Needed prime is not weak, need %s bits', weakest_needed_prime.bit_length())

    return all_combinations_are_ok and not prime_is_weak


def mode_split(secret_bytes: bytes, threshold: int, num_shares: int, prime: int, minimum_x_safe_prime: int, qr: bool, unique_name: str, showpoly: bool) -> None:
    shares, coeffs, prime = make_shares(secret=secret_bytes, threshold=threshold, num_shares=num_shares, prime=prime, minimum_x_safe_prime=minimum_x_safe_prime)
    number_format = 'decimal' if prime.bit_length() < 35 else 'hex'
    logger.warning('Generated shares:')
    prime_text = _prime_to_text(prime=prime, unique_name=unique_name, nr_bits=prime.bit_length(), threshold=threshold)
    print(f'   {prime_text}')  # print used here, as we donot want any formatting characters here!
    if qr:
        save_qr(data=prime_text, filename=f'QR-shamir_sss-{unique_name}-SP{prime.bit_length()}-T{threshold}-prime.png', is_prime=True)
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

    no_share_problems = are_generated_shares_ok(secret_bytes=secret_bytes, shares=hex_shares, threshold=threshold, prime=prime)

    logger.warning('\nPrime number used:')
    logger.info('   hex    : %s', f'{prime:X}')
    logger.debug('   decimal: %s', prime)
    logger.info('   bitsize: %s', prime.bit_length())
    if showpoly:
        logger.warning('\nPolynome coëfficiënts (const term first):')
        for i, c in enumerate(coeffs):
            logger.info('   a%s =\t%s', i, f'{c:X}')
            logger.debug('   \t%s', c)

    if not no_share_problems:
        logger.critical('\nYOU SHOULD NOT USE THESE SHARES AS THEY ARE NOT OK')


def mode_recover(shares: list[str], qr_share_files: list[str], qr_prime_file: str, primes: list[int], secret_file: str) -> None:
    found_shares = []
    if shares:
        found_shares.extend([_text_to_share(s) for s in shares])
    if qr_share_files:
        for qrfile in qr_share_files:
            text = read_qr(qrfile)
            found_shares.append(_text_to_share(text))
    if qr_prime_file:
        text = read_qr(qr_prime_file)
        prime = _text_to_prime(text=text)
        primes = [prime]

    if not found_shares:
        logger.critical('No shares provided, please use --share option')
        sys.exit(1)
    prime, secret_bytes = recover_secret(shares=found_shares, primes=primes)
    logger.warning('\nPrime number used:')
    logger.info('   hex    : %s', f'{prime:X}')
    logger.debug('   decimal: %s', prime)
    logger.info('   bitsize: %s', prime.bit_length())
    if secret_file:
        with open(secret_file, 'wb') as f:
            logger.warning('Secret written to file %s', secret_file)
            f.write(secret_bytes)
    else:
        try:
            # print used here, as we donot want any formatting characters here!
            if secret_bytes.decode() != secret_bytes.decode().strip():
                logger.warning('\nSecret (between ||), note: secret can be padded with spaces due to security reasons:')
                print(f'   |{secret_bytes.decode()}|   or   |{secret_bytes.decode().strip()}|')
            else:
                logger.warning('\nSecret (between ||):')
                print(f'   |{secret_bytes.decode()}|')
        except UnicodeDecodeError:
            logger.critical('Cannot decode secret properly with secret_bytes  |%s|', secret_bytes)


def abbreviate_hex(number: int) -> str:
    hex_str = f'{number:X}'
    hex_1 = hex_str[0]

    N = None
    for i in [32, 64, 96, 128, 160, 192, 224, 256]:
        if hex_str.startswith(hex_1 * i):
            N = i
        else:
            break

    if N is None:
        hex_str = '           ' + hex_str
    else:
        hex_str = hex_str.replace(hex_1 * N, f' {hex_1} * {N:3d} . ')

    return hex_str


def random_string(N: int) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=N))


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
        secret_string = ''
        if args.keyboard_secret:
            secret_string = input('Please type secret here:  ')
        elif args.secret:
            secret_string = args.secret
        elif args.secret_file:
            with open(args.secret_file, 'rb') as f:
                secret_bytes = f.read()
        else:
            logger.critical('Please use --keyboard-secret, --secret or --secret-file option')
            sys.exit(1)

        # if len(secret_string) < 16:
        #    logger.warning('Security size is small and vulnerable for brute force attach, padding with random chars now')
        #    random_chars = random_string(N=16 - len(secret_string) - 1)
        #    # secret_string = f'{secret_string} {random_chars}'
        #    logger.info('Secret: %s', secret_string)
        secret_bytes = secret_string.encode()
        secret_int = _to_int(secret_bytes)

        if args.strong:
            standard_primes = [standard_primes[-1]]
        prime = args.prime or get_large_enough_prime(batch=[_to_int(secret_bytes)], nr_bits=args.strength_level, primes=standard_primes)
        if not sympy.isprime(n=prime):
            logger.critical('given prime (%s) is not a prime', prime)
            sys.exit(1)
        if prime.bit_length() < 192:
            logger.critical('Security is not SAFE as a too small prime number is used')
        if secret_int > prime:
            logger.critical('Used prime number (%s) is too small for this secret (%s), should be at least: %s', prime, secret_bytes, secret_int)
            sys.exit(1)
        mode_split(
            secret_bytes=secret_bytes,
            threshold=args.threshold,
            num_shares=args.shares,
            unique_name=args.unique_name,
            prime=prime,
            minimum_x_safe_prime=args.minimum_x_safe_prime,
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
        logger.warning('Available primes:')
        for standard_prime in standard_primes:
            if args.decimal_format:
                logger.info(f' {standard_prime.bit_length():4d} -> {standard_prime}')
            else:
                if args.abbreviate:
                    logger.info(f' {standard_prime.bit_length():4d} -> 0x{abbreviate_hex(number=standard_prime)}')
                else:
                    logger.info(f' {standard_prime.bit_length():4d} -> 0x{standard_prime:X}')


if __name__ == '__main__':
    logger = logging.getLogger(Path(__file__).stem)
    main()
