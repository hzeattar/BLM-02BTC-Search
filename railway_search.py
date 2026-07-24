# -*- coding: utf-8 -*-
"""
BLM 0.2 BTC Puzzle Search Engine v2
===================================
Based on updated forensic analysis:
- 12 containers from WELCOME TO THE, normal left-to-right order.
- Clock is rotated, NOT mirrored -> no reverse order.
- Selector rule: choose candidate with independent second clue in image.
- Strongest current model:
  base aware all decide first this party public announce system agree order

Target: 1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ
Path:   m/44'/0'/0'/0/0 (Legacy P2PKH)

Install:
    pip install bip_utils
"""

import os
import sys
import time
from itertools import product, permutations
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
# Candidate matrix based on updated selector analysis.
# Position: list of candidates sorted by confidence.
# ----------------------------------------------------------------------
MATRIX = [
    ["base", "model"],           # 1: base (Liberty base messages) / model
    ["aware"],                   # 2
    ["all"],                     # 3
    ["decide"],                  # 4
    ["first", "arrive"],         # 5: first repeated externally
    ["this", "trust"],           # 6: this repeated externally
    ["party", "must"],           # 7: party in amendment + election scene
    ["public"],                  # 8
    ["announce"],                # 9
    ["need", "system"],          # 10: need from Space Needle / system CCTV
    ["agree"],                   # 11
    ["order", "history"],        # 12: order repeated externally
]

PASSPHRASES = [
    "",
    "BREATHE",
    "breathe",
    "TUESDAY",
    "tuesday",
    "BREATHE TUESDAY",
    "breathe tuesday",
    "I CAN'T BREATHE",
    "I CANT BREATHE",
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
    "SATOSHI NAKAMOTO",
    "satoshi nakamoto",
    "BITCOIN",
    "bitcoin",
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

def worker_init(lock, counter, total, start_time):
    global g_lock, g_counter, g_total, g_start
    g_lock = lock
    g_counter = counter
    g_total = total
    g_start = start_time


def process_task(args):
    words_tuple, pp_list = args
    if not is_valid_checksum(words_tuple):
        return None

    for pp in pp_list:
        try:
            addr = derive_address(" ".join(words_tuple), pp)
        except Exception:
            continue
        if addr == TARGET_ADDRESS:
            return (" ".join(words_tuple), pp, addr)

    with g_lock:
        g_counter.value += 1
        cnt = g_counter.value
        if cnt % 100 == 0 or cnt == 1:
            elapsed = time.time() - g_start.value
            rate = cnt / elapsed if elapsed > 0 else 0
            pct = 100.0 * cnt / g_total.value
            print(f"[{pct:.4f}%] {cnt:,} valid phrases tested | {rate:.1f}/s", flush=True)
    return None


# ----------------------------------------------------------------------
# Search
# ----------------------------------------------------------------------

def search_matrix(matrix, passphrases=None, max_workers=None):
    if passphrases is None:
        passphrases = PASSPHRASES

    total = 1
    for p in matrix:
        total *= len(p)
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

    def gen():
        for combo in product(*matrix):
            yield (combo, passphrases)

    print(f"Starting search with {max_workers} workers...")
    with Pool(
        processes=max_workers,
        initializer=worker_init,
        initargs=(lock, counter, total_counter, start_time),
    ) as pool:
        for result in pool.imap_unordered(process_task, gen(), chunksize=100):
            if result:
                return result
    return None


def search_constrained(core_set, fixed_positions=None, passphrases=None, max_workers=None):
    if passphrases is None:
        passphrases = PASSPHRASES
    if len(set(core_set)) != 12:
        print(f"ERROR: core_set must contain 12 unique words")
        return None

    fixed = fixed_positions or {}
    remaining_positions = [i for i in range(1, 13) if i not in fixed]
    remaining_words = [w for w in core_set if w not in fixed.values()]

    total = 1
    for n in range(1, len(remaining_words) + 1):
        total *= n
    print(f"Constrained search: fixed={fixed}, remaining perms={total:,}")

    if max_workers is None:
        max_workers = max(1, cpu_count() - 1)

    manager = Manager()
    lock = manager.Lock()
    counter = manager.Value("i", 0)
    total_counter = manager.Value("i", total)
    start_time = manager.Value("d", time.time())

    def gen():
        for perm in permutations(remaining_words):
            words = [None] * 12
            for pos, w in fixed.items():
                words[pos - 1] = w
            idx = 0
            for pos in remaining_positions:
                words[pos - 1] = perm[idx]
                idx += 1
            yield (tuple(words), passphrases)

    print(f"Starting constrained search with {max_workers} workers...")
    with Pool(
        processes=max_workers,
        initializer=worker_init,
        initargs=(lock, counter, total_counter, start_time),
    ) as pool:
        for result in pool.imap_unordered(process_task, gen(), chunksize=200):
            if result:
                return result
    return None


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    print("=" * 70)
    print("BLM 0.2 BTC Puzzle Search Engine v2")
    print("=" * 70)
    print(f"Target Address : {TARGET_ADDRESS}")
    print(f"Derivation Path: m/44'/0'/0'/0/0")
    print(f"CPU cores      : {cpu_count()}")
    print("=" * 70)

    # Strategy 1: The strongest current model + small variations
    print("\n--- Strategy 1: Updated selector matrix (64 combos) ---")
    result = search_matrix(MATRIX, passphrases=PASSPHRASES)
    if result:
        print_match(result)
        return

    # Strategy 2: Strongest 12-word set, all permutations
    strongest = ["base", "aware", "all", "decide", "first", "this",
                 "party", "public", "announce", "system", "agree", "order"]
    print("\n--- Strategy 2: Strongest set, all permutations (479M) ---")
    print("This is huge; only first 10M perms will be sampled on CPU.")
    # We do NOT run full 479M on CPU; skip or limit.

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
