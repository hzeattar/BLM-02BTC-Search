# -*- coding: utf-8 -*-
"""
BLM 0.2 BTC Puzzle Search Engine v3
===================================
Expanded search based on cumulative forensic analysis.

Search strategies:
1. Extended candidate matrix (WELCOME containers + clock + dates + visual words).
2. Full permutations of the strongest 12-word sets with checksum filter.
3. Multiple passphrases.

Target: 1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ
Path:   m/44'/0'/0'/0/0 (Legacy P2PKH)

Install:
    pip install bip_utils
"""

import os
import sys
import time
from itertools import product, permutations, islice
from multiprocessing import Pool, cpu_count, Manager

from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39Languages,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)
from mnemonic import Mnemonic

TARGET_ADDRESS = "1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ"

# ----------------------------------------------------------------------
# Extended candidate matrix
# Each position lists candidate words from the image/analysis.
# ----------------------------------------------------------------------
MATRIX = [
    # 1: subject underlined (13th Amendment Section 1); base/model from WELCOME
    ["subject", "base", "model"],
    # 2: aware from WELCOME
    ["aware"],
    # 3: all from WELCOME; tower from clock (1+2=3)
    ["all", "tower"],
    # 4: decide from WELCOME
    ["decide"],
    # 5: first from WELCOME / repeated externally; arrive alternative
    ["first", "arrive"],
    # 6: this from WELCOME / repeated externally; trust alternative
    ["this", "trust"],
    # 7: party from WELCOME / amendment; must alternative
    ["party", "must"],
    # 8: public from WELCOME
    ["public"],
    # 9: announce from WELCOME
    ["announce"],
    # 10: need/system from WELCOME; food from Space Needle if position 10
    ["need", "system", "food"],
    # 11: agree from WELCOME; food from Space Needle if position 11
    ["agree", "food"],
    # 12: order/history from WELCOME; black from Rune X=10 if position 10
    ["order", "history", "black"],
]

# Full candidate word pool for permutation searches
CANDIDATE_POOL = sorted(set([
    # WELCOME containers
    "base", "model", "aware", "all", "decide", "first", "arrive",
    "this", "trust", "party", "must", "public", "announce",
    "need", "system", "agree", "history", "order",
    # Visual/clock words
    "moon", "tower", "food", "subject", "real", "black",
    # BIP39 index words from dates/numbers
    "dose", "mean", "trouble", "wise", "air",
    # Documented community candidates (lower confidence)
    "camera", "mask", "police", "liberty", "eye", "pyramid", "vote",
    "rifle", "gold", "glove", "apple", "peace", "future", "world", "welcome",
]))

PASSPHRASES = [
    "",
    "BREATHE",
    "breathe",
    "Breath",
    "BREATH",
    "TUESDAY",
    "tuesday",
    "BREATHE TUESDAY",
    "breathe tuesday",
    "I CAN'T BREATHE",
    "I CANT BREATHE",
    "ICANTBREATHE",
    "BLACK LIVES MATTER",
    "BLM",
    "ONLY REAL BITCOIN",
    "ONLY BITCOIN",
    "ORDER AND STABILITY",
    "THIS IS THE FIRST PREDICTION",
    "WELCOME TO THE BRAVE NEW WORLD",
    "PAY FOR THE FUTURE",
    "FUCK THIS SHIT",
    "RERUM COGNOSCERE CAUSAS",
    "FIAT JUSTITIA ET PEREAT MUNDUS",
    "UBI BENE IBI PATRIA",
    "George Floyd",
    "GEORGE FLOYD",
    "2000",
    "0.2",
    "0.20107284",
    "SATOSHI NAKAMOTO",
    "satoshi nakamoto",
    "BITCOIN",
    "bitcoin",
    "X",
    "SUN",
    "MOON",
    "TOWER",
    "1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ",
]

mnemo = Mnemonic("english")
wordset = set(mnemo.wordlist)
validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)


def derive_address(mnemonic: str, passphrase: str) -> str:
    seed_bytes = Bip39SeedGenerator(mnemonic, Bip39Languages.ENGLISH).Generate(passphrase)
    bip44_ctx = (
        Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    return bip44_ctx.PublicKey().ToAddress()


def is_valid_checksum(words):
    return validator.IsValid(" ".join(words))


# ----------------------------------------------------------------------
# Worker
# ----------------------------------------------------------------------

def worker_init(lock, counter, total, start_time, found_event):
    global g_lock, g_counter, g_total, g_start, g_found
    g_lock = lock
    g_counter = counter
    g_total = total
    g_start = start_time
    g_found = found_event


def process_task(args):
    if g_found.is_set():
        return None

    words_tuple, pp_list = args
    if not is_valid_checksum(words_tuple):
        return None

    mnemonic = " ".join(words_tuple)
    for pp in pp_list:
        try:
            addr = derive_address(mnemonic, pp)
        except Exception:
            continue
        if addr == TARGET_ADDRESS:
            g_found.set()
            return (mnemonic, pp, addr)

    with g_lock:
        g_counter.value += 1
        cnt = g_counter.value
        if cnt % 500 == 0 or cnt == 1:
            elapsed = time.time() - g_start.value
            rate = cnt / elapsed if elapsed > 0 else 0
            pct = 100.0 * cnt / g_total.value
            print(f"[{pct:.6f}%] {cnt:,} valid phrases tested | {rate:.1f}/s", flush=True)
    return None


# ----------------------------------------------------------------------
# Search functions
# ----------------------------------------------------------------------

def count_combinations(matrix):
    total = 1
    for p in matrix:
        total *= len(p)
    return total


def search_matrix(matrix, passphrases=None, max_workers=None):
    if passphrases is None:
        passphrases = PASSPHRASES

    total = count_combinations(matrix)
    print(f"Matrix sizes: {[len(p) for p in matrix]}")
    print(f"Total combinations: {total:,}")
    print(f"Passphrases: {len(passphrases)}")

    for i, p in enumerate(matrix, 1):
        bad = [w for w in p if w not in wordset]
        if bad:
            print(f"WARNING position {i} has non-BIP39 words: {bad}")

    if max_workers is None:
        max_workers = max(1, cpu_count() - 1)

    manager = Manager()
    lock = manager.Lock()
    counter = manager.Value("i", 0)
    total_counter = manager.Value("i", total)
    start_time = manager.Value("d", time.time())
    found_event = manager.Event()

    def gen():
        for combo in product(*matrix):
            if found_event.is_set():
                break
            yield (combo, passphrases)

    print(f"Starting search with {max_workers} workers...")
    with Pool(
        processes=max_workers,
        initializer=worker_init,
        initargs=(lock, counter, total_counter, start_time, found_event),
    ) as pool:
        for result in pool.imap_unordered(process_task, gen(), chunksize=200):
            if result:
                return result
    return None


def search_permutation_set(core_set, passphrases=None, max_workers=None, limit=None):
    """Search all permutations of a 12-word set."""
    if passphrases is None:
        passphrases = PASSPHRASES
    if len(set(core_set)) != 12:
        print(f"ERROR: core_set must contain 12 unique words")
        return None

    total = 479001600  # 12!
    print(f"Permutation search: 12! = {total:,}")
    if limit:
        print(f"Limit: first {limit:,} permutations")

    if max_workers is None:
        max_workers = max(1, cpu_count() - 1)

    manager = Manager()
    lock = manager.Lock()
    counter = manager.Value("i", 0)
    total_counter = manager.Value("i", limit or total)
    start_time = manager.Value("d", time.time())
    found_event = manager.Event()

    def gen():
        it = permutations(core_set)
        if limit:
            it = islice(it, limit)
        for perm in it:
            if found_event.is_set():
                break
            yield (perm, passphrases)

    print(f"Starting permutation search with {max_workers} workers...")
    with Pool(
        processes=max_workers,
        initializer=worker_init,
        initargs=(lock, counter, total_counter, start_time, found_event),
    ) as pool:
        for result in pool.imap_unordered(process_task, gen(), chunksize=1000):
            if result:
                return result
    return None


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    print("=" * 70)
    print("BLM 0.2 BTC Puzzle Search Engine v3")
    print("=" * 70)
    print(f"Target Address : {TARGET_ADDRESS}")
    print(f"Derivation Path: m/44'/0'/0'/0/0")
    print(f"CPU cores      : {cpu_count()}")
    print("=" * 70)

    # Strategy 1: Extended matrix search
    print("\n--- Strategy 1: Extended candidate matrix ---")
    result = search_matrix(MATRIX, passphrases=PASSPHRASES)
    if result:
        print_match(result)
        return

    # Strategy 2: Full permutations of strongest set
    strongest = ["base", "aware", "all", "decide", "first", "this",
                 "party", "public", "announce", "system", "agree", "order"]
    print("\n--- Strategy 2: Full permutations of strongest set ---")
    result = search_permutation_set(strongest, passphrases=PASSPHRASES[:10], limit=10_000_000)
    if result:
        print_match(result)
        return

    # Strategy 3: Full permutations of mixed high-confidence set
    mixed = ["subject", "tower", "food", "black", "moon", "dose",
             "mean", "trouble", "wise", "real", "this", "order"]
    print("\n--- Strategy 3: Full permutations of mixed visual/index set ---")
    result = search_permutation_set(mixed, passphrases=PASSPHRASES[:10], limit=10_000_000)
    if result:
        print_match(result)
        return

    print("\n" + "=" * 70)
    print("All strategies completed. No match found.")
    print("=" * 70)


def print_match(result):
    mnemonic, passphrase, address = result
    print("\n" + "!" * 70)
    print(">>> MATCH FOUND <<<")
    print("!" * 70)
    print(f"Mnemonic  : {mnemonic}")
    print(f"Passphrase: {passphrase!r}")
    print(f"Address   : {address}")
    print("!" * 70)
    sys.exit(0)


if __name__ == "__main__":
    main()
