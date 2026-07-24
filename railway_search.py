# -*- coding: utf-8 -*-
"""
BLM 0.2 BTC Puzzle Search Engine
================================
Searches constrained BIP39 mnemonic permutations for the target Bitcoin address:
    1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ

Based on forensic analysis of the BLM 0.2 BTC puzzle image.
Search strategy:
    - Generate candidate words from visual/positional clues.
    - Validate BIP39 checksum first (cheap).
    - Derive P2PKH address at m/44'/0'/0'/0/0.
    - Test multiple passphrases.

Install:
    pip install bip_utils
"""

import os
import sys
import time
import hashlib
from itertools import permutations, product, islice
from multiprocessing import Pool, cpu_count, Manager, Lock

from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39Languages,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)
from mnemonic import Mnemonic

# ----------------------------------------------------------------------
# Target
# ----------------------------------------------------------------------
TARGET_ADDRESS = "1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ"

# ----------------------------------------------------------------------
# Candidate words from forensic analysis
# ----------------------------------------------------------------------

# High-confidence words from direct visual evidence
CORE_WORDS = [
    "moon",      # written on clock second hand
    "tower",     # written on clock minute hand
    "food",      # written vertically on Space Needle
    "subject",   # underlined on statue (13th Amendment Section 1)
    "real",      # "ONLY REAL BITCOIN" at Statue of Liberty base
    "black",     # BLM + "black day number X"
]

# Words derived from BIP39 indices of explicit numbers in the image
INDEX_WORDS = [
    "dose",      # 05.25 -> 525 (1-based BIP39)
    "mean",      # 11.03 -> 1103 (1-based BIP39)
    "trouble",   # 1865 (1-based BIP39)
    "wise",      # 2020 (1-based BIP39)
    "air",       # 44 stars -> BIP44 -> word 44
]

# Words from WELCOME TO THE Whitepaper containers (last-BIP39 rule)
WELCOME_WORDS = [
    "base",      # from "based" at container W (external clue: Statue base)
    "aware",
    "all",
    "decide",    # from "decided"
    "first",     # repeated externally
    "this",      # repeated externally; alternative to "trust"
    "party",     # external clue: 13th Amendment / political parties
    "must",      # alternative to "party"
    "public",    # from "publicly"
    "announce",  # from "announced"
    "need",      # hidden in Space Needle; alternative to "system"
    "system",    # alternative to "need"
    "agree",
    "order",     # repeated externally; alternative to "history"
    "history",   # alternative to "order"
]

# Documented community position table (HomelessPhD/BLM_0.2BTC)
# These are NOT confirmed; use as fallback candidates.
COMMUNITY_WORDS = [
    "camera", "mask", "police", "liberty", "eye",
    "pyramid", "vote", "rifle", "gold", "glove",
    "apple", "peace", "future", "world", "welcome",
]

# ----------------------------------------------------------------------
# Passphrases to test
# ----------------------------------------------------------------------
PASSPHRASES = [
    "",
    "BREATHE",
    "breathe",
    "TUESDAY",
    "tuesday",
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
    "RERUM COGNOSCERE CAUSAS",
    "FIAT JUSTITIA ET PEREAT MUNDUS",
    "UBI BENE IBI PATRIA",
    "2000",
    "0.2",
    "0.20107284",
    "SATOSHI NAKAMOTO",
    "satoshi nakamoto",
    "George Floyd",
    "GEORGE FLOYD",
    "X",
    "BTC",
    "bitcoin",
    "BITCOIN",
    "1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ",
]

# ----------------------------------------------------------------------
# Build candidate pools per position
# Pools are lists of candidate words for each of the 12 positions.
# Later we can constrain further (e.g. tower=3, subject=1).
# ----------------------------------------------------------------------

def build_pools(fixed_positions=None):
    """
    Build 12 candidate pools.
    fixed_positions: dict {1-based position: word}
    """
    fixed = fixed_positions or {}
    all_candidates = sorted(set(CORE_WORDS + INDEX_WORDS + WELCOME_WORDS + COMMUNITY_WORDS))

    pools = [list(all_candidates) for _ in range(12)]

    # Apply known high-confidence positional hints (can be disabled)
    hints = {
        1: ["subject"],          # Section 1 / subject underlined
        3: ["tower"],            # clock minute hand 1+2=3
        10: ["black"],           # X=10 / black day
        11: ["food"],            # Space Needle position 11
        13: ["moon"],            # clock second hand 12+1=13 (for 24-word, ignored here)
    }
    # Only apply if not overridden by fixed_positions
    for pos, words in hints.items():
        if pos <= 12 and pos not in fixed:
            # Intersect with candidates so we keep valid BIP39 words only
            valid = [w for w in words if w in all_candidates]
            if valid:
                pools[pos - 1] = valid

    # Apply explicit fixed positions
    for pos, word in fixed.items():
        if 1 <= pos <= 12:
            pools[pos - 1] = [word]

    return pools

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

mnemo = Mnemonic("english")
wordset = set(mnemo.wordlist)
validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)


def is_bip39_word(w):
    return w in wordset


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
# Worker for full search with candidate pools
# ----------------------------------------------------------------------

def worker_init(lock, counter, total, start_time, match_event):
    global g_lock, g_counter, g_total, g_start, g_match_event
    g_lock = lock
    g_counter = counter
    g_total = total
    g_start = start_time
    g_match_event = match_event


def process_permutation(args):
    words_tuple, pp_list = args
    if not is_valid_checksum(words_tuple):
        return None

    # Check passphrases
    for pp in pp_list:
        try:
            addr = derive_address(" ".join(words_tuple), pp)
        except Exception:
            continue
        if addr == TARGET_ADDRESS:
            return (" ".join(words_tuple), pp, addr)

    # Progress
    if hasattr(g_lock, "acquire"):
        with g_lock:
            g_counter.value += 1
            cnt = g_counter.value
            if cnt % 1000 == 0 or cnt == 1:
                elapsed = time.time() - g_start.value
                rate = cnt / elapsed if elapsed > 0 else 0
                pct = 100.0 * cnt / g_total.value
                print(f"[{pct:.4f}%] {cnt:,} valid checksum phrases tested | {rate:.1f}/s", flush=True)
    return None


# ----------------------------------------------------------------------
# Search strategies
# ----------------------------------------------------------------------

def search_full_pools(pools, passphrases=None, max_workers=None):
    """Brute-force all permutations from candidate pools."""
    if passphrases is None:
        passphrases = PASSPHRASES

    total = 1
    for p in pools:
        total *= len(p)
    print(f"Pool sizes: {[len(p) for p in pools]}")
    print(f"Total cartesian permutations: {total:,}")

    # Validate all words are BIP39
    for i, p in enumerate(pools, 1):
        bad = [w for w in p if not is_bip39_word(w)]
        if bad:
            print(f"WARNING position {i} has non-BIP39 words: {bad}")

    if max_workers is None:
        max_workers = max(1, cpu_count() - 1)

    manager = Manager()
    lock = manager.Lock()
    counter = manager.Value("i", 0)
    total_counter = manager.Value("i", total)
    start_time = manager.Value("d", time.time())
    match_event = manager.Event()

    # Build generator of (words_tuple, passphrases)
    def gen():
        for combo in product(*pools):
            yield (combo, passphrases)

    print(f"Starting search with {max_workers} workers...")
    with Pool(
        processes=max_workers,
        initializer=worker_init,
        initargs=(lock, counter, total_counter, start_time, match_event),
    ) as pool:
        for result in pool.imap_unordered(process_permutation, gen(), chunksize=200):
            if result:
                return result
    return None


def search_constrained_pool(core_set, fixed_positions=None, passphrases=None, max_workers=None):
    """
    Take a 12-word candidate set and search permutations with some fixed positions.
    core_set: list of exactly 12 candidate words.
    """
    if passphrases is None:
        passphrases = PASSPHRASES
    if len(set(core_set)) != 12:
        print(f"ERROR: core_set must contain 12 unique words, got {len(set(core_set))}")
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
    match_event = manager.Event()

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
        initargs=(lock, counter, total_counter, start_time, match_event),
    ) as pool:
        for result in pool.imap_unordered(process_permutation, gen(), chunksize=500):
            if result:
                return result
    return None


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    print("=" * 70)
    print("BLM 0.2 BTC Puzzle Search Engine")
    print("=" * 70)
    print(f"Target Address : {TARGET_ADDRESS}")
    print(f"Derivation Path: m/44'/0'/0'/0/0 (Legacy P2PKH)")
    print(f"CPU cores      : {cpu_count()}")
    print("=" * 70)

    # Strategy 1: Constrained search on highest-confidence 12-word set
    # Based on analysis: core words + index words, with positional hints.
    core12 = ["subject", "tower", "food", "black", "moon", "dose", "mean", "trouble", "wise", "real", "this", "order"]
    print("\n--- Strategy 1: High-confidence 12-word set with positional hints ---")
    result = search_constrained_pool(
        core12,
        fixed_positions={1: "subject", 3: "tower", 10: "black", 11: "food"},
        passphrases=PASSPHRASES,
    )
    if result:
        print_match(result)
        return

    # Strategy 2: Slightly relaxed positional hints
    print("\n--- Strategy 2: Same set, only subject=1 and tower=3 fixed ---")
    result = search_constrained_pool(
        core12,
        fixed_positions={1: "subject", 3: "tower"},
        passphrases=PASSPHRASES,
    )
    if result:
        print_match(result)
        return

    # Strategy 3: WELCOME TO THE container words, no fixed positions
    welcome12 = ["base", "aware", "all", "decide", "first", "this", "party", "public", "announce", "need", "agree", "order"]
    print("\n--- Strategy 3: WELCOME TO THE container words (first-BIP39 rule) ---")
    result = search_constrained_pool(
        welcome12,
        fixed_positions={},
        passphrases=PASSPHRASES,
    )
    if result:
        print_match(result)
        return

    # Strategy 4: Mixed pool full search (smaller pool)
    print("\n--- Strategy 4: Mixed candidate pool full search ---")
    pools = build_pools()
    # Limit pool sizes to keep search feasible on CPU
    for i, p in enumerate(pools):
        if len(p) > 20:
            pools[i] = p[:20]
    result = search_full_pools(pools, passphrases=PASSPHRASES[:10])
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
