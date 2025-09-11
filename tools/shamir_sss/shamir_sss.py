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
import logging
import qrcode
import random
import sys
from pathlib import Path
from pyzbar.pyzbar import decode
from PIL import Image

__author__ = "MCMD"
__copyright__ = "Copyright 2025, MCMD"
__license__ = "MIT"
__version__ = "2025-09.01"


class CustomFormatter(logging.Formatter):
    """
    logging
    """

    grey = "\x1b[38;2;152;152;152m"
    grey_background = grey.replace("38", "48")
    white = "\x1b[38;2;224;242;224m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    msg_format = "%(message)s"

    FORMATS = {
        logging.DEBUG: grey + msg_format + reset,
        logging.INFO: white + msg_format + reset,
        logging.WARNING: yellow + msg_format + reset,
        logging.ERROR: red + msg_format + reset,
        logging.CRITICAL: bold_red + msg_format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%H:%M:%S")
        return formatter.format(record)


def get_arguments() -> argparse.Namespace:
    """
    get commandline arguments
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Shamir Secret Sharing arguments", epilog="© Marcel Dorenbos, 2025"
    )
    choices = ["debug", "info", "warning", "error", "critical"]
    parser.add_argument(
        "--log-level",
        help="Set log level (default '%(default)s')",
        choices=choices,
        default="debug",
    )
    parser.add_argument(
        "-V", "--version", action="version", version="%(prog)s " + __version__
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    epilog = """

Example call:
-------------
   $ %(prog)s  --secret Secret --threshold 2  --shares 3
   Generated shares:
         9d5ee6-M127-T2-1-105cfefbc7089132e332d5e59f44943c
         9d5ee6-M127-T2-2-20b9fdf78e112265c6655865db16c304
         9d5ee6-M127-T2-3-3116fcf35519b398a997dae616e8f1cc

   Prime number used:
      decimal: 170141183460469231731687303715884105727
      hex    : 0x7fffffffffffffffffffffffffffffff
      bitsize: 127


Structure share:
----------------
An example share looks like: 9d5ee6-M127-T2-3-3116fcf35519b398a997dae616e8f1cc

This has the following elements:
. 9d5ee6: this is a random number that is used to identify all shares belonging to each other.
          So for all shares this number MUST be te same!
. M127  : this is refering to a Mersenne prime number with 127 bits. You can find these here:
          https://en.wikipedia.org/wiki/Mersenne_prime#List_of_known_Mersenne_primes
. T2    : this is refering to the number of different shares NEEDED to calculate the secret
. 3     : this is the share with x-value=3
. HEX   : the y-value for this share in HEX is: 3116fcf35519b398a997dae616e8f1cc

        """
    p_split = sub.add_parser(
        "split", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog
    )
    p_split.add_argument("-S", "--secret")
    p_split.add_argument("--infile", help="file with the secret")
    p_split.add_argument("-t", "--threshold", type=int, required=True)
    p_split.add_argument("-s", "--shares", type=int, required=True)
    p_split.add_argument(
        "--strength-level",
        type=int,
        help="minimum prime length in bits (default '%(default)s')",
        default=127,
    )
    p_split.add_argument(
        "--use-small-primes",
        help="Use the smallest possible prime for polynome",
        action="store_true",
    )
    p_split.add_argument("--qr", help="Generate QR-code files", action="store_true")
    p_split.add_argument(
        "--strong", help="Strongest possible security", action="store_true"
    )
    p_split.add_argument(
        "--showpoly", help="Show the polynome coëfficiënts", action="store_true"
    )

    epilog = """

Example call:
-------------
   $ %(prog)s  --share 9d5ee6-M127-T2-2-20b9fdf78e112265c6655865db16c304 --share 9d5ee6-M127-T2-3-3116fcf35519b398a997dae616e8f1cc
   Prime number used:
      decimal: 170141183460469231731687303715884105727
      hex    : 0x7fffffffffffffffffffffffffffffff
      bitsize: 127

   Secret:
   Secret

So the secret is found here ("Secret").
It also shows the prime numbers used for the calculations. This SHOULD be the same as used when generating the shares.
        """
    p_recover = sub.add_parser(
        "recover", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog
    )
    p_recover.add_argument(
        "-s", "--share", action="append", help="share data, use option multiple times"
    )
    p_recover.add_argument(
        "-q",
        "--qrfile",
        action="append",
        help="QR-code bestand met share, use option multiple times",
    )
    p_recover.add_argument("--outfile", help="outfile with secret")

    p_primes = sub.add_parser(
        "primes", description="Show the used Mersenne prime numbers"
    )
    p_primes.add_argument("--list", help="List prime numbers", action="store_true")
    p_primes.add_argument(
        "--decimal-format",
        help="Show primes in decimal format instead of hex format",
        action="store_true",
    )

    return parser.parse_args()


def get_mersenne_primes() -> list:
    """Returns all the mersenne primes with less than 500 digits."""
    mersenne_prime_exponents = [
        2,
        3,
        5,
        7,
        13,
        17,
        19,
        31,
        61,
        89,
        107,
        127,
        521,
        607,
        1279,
    ]
    primes = []
    for exp in mersenne_prime_exponents:
        prime = 1
        for _ in range(exp):
            prime *= 2
        prime -= 1
        primes.append(prime)
    return sorted(primes)


def get_large_enough_prime(batch: list[int], nr_bits: int, primes: list[int]) -> int:
    """Returns a prime number that is greater all the numbers in the batch."""
    max_batch = max(batch + [0])
    max_bit_length_batch = (max_batch.bit_length() // 8 + 2) * 8

    for prime in primes:
        if prime.bit_length() < nr_bits:
            continue
        if prime.bit_length() > max_bit_length_batch:
            return prime

    logger.critical(
        f"Error! Cannot find prime with bit length of at least {nr_bits} bits!"
    )
    sys.exit(1)


def _to_int(secret: bytes) -> int:
    return int.from_bytes(secret, byteorder="big")


def _from_int(i: int) -> bytes:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder="big")


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


def make_shares(
    secret: bytes, threshold: int, num_shares: int, prime: int
) -> tuple[list[tuple[int, int]], list[int], int]:
    secret_int = _to_int(secret)
    coeffs = [secret_int] + [
        random.randrange(start=prime // 128, stop=prime) for _ in range(threshold - 1)
    ]
    shares = [(x, _eval_poly(coeffs, x, prime)) for x in range(1, num_shares + 1)]
    return shares, coeffs, prime


def recover_secret(
    shares: list[tuple[int, int]], primes: list[int]
) -> tuple[int, bytes]:
    idx, nr_bits, threshold, x_s, y_s = zip(*shares)
    if len(set(idx)) != 1:
        logger.critical("Error! set of shares do not belong to each other (IDX wrong)")
        sys.exit(1)
    if len(set(nr_bits)) != 1:
        logger.critical(
            "Error! set of shares do not belong to each other (#bits wrong)"
        )
        sys.exit(1)
    if len(set(threshold)) != 1:
        logger.critical(
            "Error! set of shares do not belong to each other (threshold wrong)"
        )
        sys.exit(1)

    if len(shares) < threshold[0]:
        logger.critical(
            "For this secret I need %s shares, but I only got %s shares",
            threshold[0],
            len(shares),
        )
        sys.exit(1)

    prime = get_large_enough_prime(batch=[], nr_bits=nr_bits[0], primes=primes)
    secret_int = _lagrange_interpolate(x=0, x_s=list(x_s), y_s=list(y_s), prime=prime)
    return prime, _from_int(secret_int)


def _share_to_text(
    share: tuple[int, int],
    nr_bits,
    idx: str,
    threshold: int,
    number_format: str = "hex",
) -> str:
    x, y = share
    partial_string = f"{idx}-M{nr_bits}-T{threshold}-{x}"
    if number_format == "decimal":
        return f'{' ' * len(partial_string)} {y:<10} DECIMAL:  NEVER USE THIS FOR RECOVERY, IT WILL NOT WORK'
    elif number_format == "hex":
        return f"{partial_string}-{y:X}"

    logger.critical("Unknown number format used in _share_to_text")
    sys.exit(1)


def _text_to_share(text: str) -> tuple[str, int, int, int, int]:
    idx, nr_bits, threshold, x_str, y_hex = text.split("-", 4)
    return idx, int(nr_bits[1:]), int(threshold[1:]), int(x_str), int(y_hex, 16)


def save_qr(data: str, filename: str) -> None:
    img = qrcode.make(data)
    img.save(filename)
    logger.debug("     Saving share to QR-code file %s", filename)


def read_qr(filename: str) -> list[str]:
    img = Image.open(filename)
    decoded_objs = decode(img)
    results = [obj.data.decode("utf-8") for obj in decoded_objs]
    return results


def mode_split(
    secret_bytes: bytes,
    threshold: int,
    num_shares: int,
    prime: int,
    qr: bool,
    showpoly: bool,
) -> None:
    shares, coeffs, prime = make_shares(
        secret=secret_bytes, threshold=threshold, num_shares=num_shares, prime=prime
    )
    unique_idx = f"{random.randrange(2**24):x}"
    number_format = "decimal" if prime.bit_length() < 35 else "hex"
    logger.warning("Generated shares:")
    for idx, s in enumerate(shares):
        share_text = _share_to_text(
            share=s,
            idx=unique_idx,
            nr_bits=prime.bit_length(),
            threshold=threshold,
            number_format="hex",
        )
        print(
            f"   {share_text}"
        )  # print used here, as we donot want any formatting characters here!

        if qr:
            save_qr(
                share_text,
                f"QR-shamir_sss-{unique_idx}-M{prime.bit_length()}-T{threshold}-{idx+1}.png",
            )

        if number_format == "decimal":
            share_text_decimal = _share_to_text(
                share=s,
                idx=unique_idx,
                nr_bits=prime.bit_length(),
                threshold=threshold,
                number_format="decimal",
            )
            logger.debug("   %s", share_text_decimal)

    logger.warning("\nPrime number used:")
    logger.info("   decimal: %s", prime)
    logger.info("   hex    : %s", hex(prime))
    logger.info("   bitsize: %s", prime.bit_length())
    if showpoly:
        logger.warning("\nPolynome coëfficiënts (const term first):")
        for i, c in enumerate(coeffs):
            logger.info("   a%s =\t%s", i, hex(c))
            logger.debug("   \t%s", c)


def mode_recover(
    shares: list[str], qrfiles: list[str], primes: list[int], out: str
) -> None:
    found_shares = []
    if shares:
        found_shares.extend([_text_to_share(s) for s in shares])
    if qrfiles:
        for qrfile in qrfiles:
            texts = read_qr(qrfile)
            for t in texts:
                found_shares.append(_text_to_share(t))
    if not found_shares:
        logger.critical("No shares provided, please use --share option")
        sys.exit(1)
    prime, secret_bytes = recover_secret(found_shares, primes=primes)
    logger.warning("\nPrime number used:")
    logger.info("   decimal: %s", prime)
    logger.info("   hex    : %s", hex(prime))
    logger.info("   bitsize: %s", prime.bit_length())
    if out:
        with open(out, "wb") as f:
            logger.warning("Secret written to file %s", out)
            f.write(secret_bytes)
    else:
        try:
            logger.warning("\nSecret:")
            logger.info("%s", secret_bytes.decode())
        except UnicodeDecodeError:
            logger.critical(secret_bytes)


def main() -> None:
    args = get_arguments()

    # create logger with 'spam_application'
    logger = logging.getLogger(Path(__file__).stem)
    logger.setLevel(level=args.log_level.upper())

    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)

    standard_primes = get_mersenne_primes()  # support secrets up to 160 characters

    #  ┌──────────────────────────────────────┐
    #  │                                      │
    #  │ ███████╗██████╗ ██╗     ██╗████████╗ │
    #  │ ██╔════╝██╔══██╗██║     ██║╚══██╔══╝ │
    #  │ ███████╗██████╔╝██║     ██║   ██║    │
    #  │ ╚════██║██╔═══╝ ██║     ██║   ██║    │
    #  │ ███████║██║     ███████╗██║   ██║    │
    #  │ ╚══════╝╚═╝     ╚══════╝╚═╝   ╚═╝    │
    #  └──────────────────────────────────────┘
    if args.cmd == "split":
        if args.strength_level < 127:
            logger.critical(
                "Security is not SAFE as a too small prime could be used for security reasons"
            )
        if args.strong:
            standard_primes = [standard_primes[-1]]

        if args.secret:
            secret_bytes = args.secret.encode()
        elif args.infile:
            with open(args.infile, "rb") as f:
                secret_bytes = f.read()
        else:
            logger.critical("Please use --secret or --infile option")
            sys.exit(1)
        prime = get_large_enough_prime(
            batch=[_to_int(secret_bytes)],
            nr_bits=args.strength_level,
            primes=standard_primes,
        )
        mode_split(
            secret_bytes=secret_bytes,
            threshold=args.threshold,
            num_shares=args.shares,
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
    elif args.cmd == "recover":
        mode_recover(
            shares=args.share,
            qrfiles=args.qrfile,
            primes=standard_primes,
            out=args.outfile,
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
    elif args.cmd == "primes":
        if args.list:
            logger.warning("Available primes:")
            for standard_prime in standard_primes:
                if args.decimal_format:
                    logger.info(
                        f" {standard_prime.bit_length():4d} -> {standard_prime}"
                    )
                else:
                    logger.info(
                        f" {standard_prime.bit_length():4d} -> 0x{standard_prime:x}"
                    )


if __name__ == "__main__":
    logger = logging.getLogger(Path(__file__).stem)
    main()
