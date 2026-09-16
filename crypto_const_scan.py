# Scan a program for cryptographic, checksum, hash and algorithmic constants
#@author Clifton Wolfe
#@category Analysis
#
# Searches memory for the constant tables that identify an algorithm even when
# every symbol has been stripped: SHA-2 round tables, AES S-boxes and T-tables,
# CRC tables, Blowfish's digits of pi, DES permutations, curve parameters and
# so on. Each constant is searched for in every layout it could plausibly have
# -- big and little endian, packed as u8/u16/u32/u64, split word-swapped, and
# for bignums stored limb-reversed -- because the same table looks quite
# different in a 32-bit ARM firmware image and an x86-64 shared object.
#
# Headless:
#   analyzeHeadless <proj> <name> -process <bin> -postScript crypto_const_scan.py
#   ... -postScript crypto_const_scan.py bookmark label category=hash,cipher
#
# Arguments (all optional, any order):
#   bookmark            add a note bookmark at each match
#   label               add a primary label at each match
#   scalars             also report single-word constants (noisy)
#   complete            only report constants that verified in full
#   category=a,b        restrict to these categories
#   name=text           restrict to signatures whose name contains "text"
#   align=N             only report matches at addresses that are multiples of N

from __main__ import *

from ghidra.program.model.symbol import SourceType
from ghidra_api.const_scan_utils import CryptoConstScanner
from ghidra_api.crypto_const_utils import CATEGORIES, get_signatures

import logging

log = logging.getLogger(__file__)
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

BOOKMARK_CATEGORY = "Crypto Constants"
# Ghidra rejects some punctuation in symbol names, and a label is easier to
# search for without it.
_LABEL_SAFE = ("abcdefghijklmnopqrstuvwxyz"
               "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def parse_args(args):
    options = {"bookmark": False, "label": False, "scalars": False,
               "complete": False, "categories": None, "names": None,
               "alignment": 1}
    for arg in args:
        arg = str(arg)
        if arg in ("bookmark", "label", "scalars", "complete"):
            options[arg] = True
        elif arg.startswith("category="):
            options["categories"] = [c.strip() for c in
                                     arg.split("=", 1)[1].split(",") if c.strip()]
        elif arg.startswith("name="):
            options["names"] = [arg.split("=", 1)[1]]
        elif arg.startswith("align="):
            options["alignment"] = int(arg.split("=", 1)[1], 0)
        else:
            raise ValueError("unrecognised argument %r" % arg)
    unknown = set(options["categories"] or ()) - set(CATEGORIES)
    if unknown:
        raise ValueError("unknown categor(y/ies) %s; known: %s"
                         % (", ".join(sorted(unknown)), ", ".join(CATEGORIES)))
    return options


def label_name(match):
    """A symbol name for a match, e.g. ``SHA_256_round_constants_u32be``."""
    text = "%s_%s" % (match.name, match.layout)
    cleaned = "".join(c if c in _LABEL_SAFE else "_" for c in text)
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned.strip("_")


def annotate(match, options):
    """Bookmark and/or label a match. Caller owns the transaction."""
    if options["bookmark"]:
        extent = ("complete" if match.is_complete
                  else "%d of %d words" % (match.words_matched,
                                           match.word_count))
        createBookmark(match.address, BOOKMARK_CATEGORY,
                       "%s (%s, %s)" % (match.name, match.layout, extent))
    if options["label"]:
        # A user-set label at the address already says something more specific
        # than this script can, so leave it alone.
        existing = getSymbolAt(match.address)
        if existing is not None and existing.getSource() == SourceType.USER_DEFINED:
            log.info("keeping existing label %s at %s", existing.getName(),
                     match.address)
            return
        createLabel(match.address, label_name(match), True,
                    SourceType.ANALYSIS)


def script_args():
    """This script's arguments, however it was launched.

    getScriptArgs() exists under Ghidra's own script providers; the pyghidra
    CLI passes them through sys.argv instead.
    """
    try:
        return list(getScriptArgs())
    except NameError:
        import sys
        return sys.argv[1:]


def run():
    options = parse_args(script_args())

    signatures = get_signatures(categories=options["categories"],
                                include_scalars=options["scalars"],
                                names=options["names"])
    if not signatures:
        print("[-] No signatures selected")
        return None

    log.info("[+] Scanning %s for %d constant signature(s)",
             currentProgram.getName(), len(signatures))

    scanner = CryptoConstScanner(signatures=signatures,
                                 alignment=options["alignment"],
                                 min_words_matched=None)
    scanner.scan()
    if options["complete"]:
        scanner.matches = [m for m in scanner.matches if m.is_complete]
    scanner.print_matches()

    if scanner.matches and (options["bookmark"] or options["label"]):
        transaction = currentProgram.startTransaction("Annotate crypto constants")
        try:
            for match in scanner.matches:
                annotate(match, options)
            currentProgram.endTransaction(transaction, True)
            log.info("[+] Annotated %d match(es)", len(scanner.matches))
        except:  # noqa: E722 - Ghidra throws Java exceptions, not Exception
            currentProgram.endTransaction(transaction, False)
            raise
    return scanner


scanner = run()
