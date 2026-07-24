# -*- coding: utf-8 -*-
"""
BIP39 Puzzle Solver - SecretScan
--------------------------------
Tests a 12-container matrix of BIP39 mnemonic combinations (64 permutations),
validates checksums, derives Legacy P2PKH addresses at m/44'/0'/0'/0/0,
and matches them against a target address.

Install dependency:
    pip install bip_utils
"""

import sys
from itertools import product

from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip39Languages,
    Bip44,
    Bip44Coins,
    Bip44Changes,
)

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

TARGET_ADDRESS = "1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ"

# 12-word matrix in strict order (positions 1..12)
MATRIX = [
    ["base", "model"],      # Position 1
    ["aware"],              # Position 2
    ["all"],                # Position 3
    ["decide"],             # Position 4
    ["first", "arrive"],    # Position 5
    ["this", "trust"],      # Position 6
    ["party", "must"],      # Position 7
    ["public"],             # Position 8
    ["announce"],           # Position 9
    ["system", "need"],     # Position 10
    ["agree"],              # Position 11
    ["order", "history"],   # Position 12
]

# Empty passphrase has highest probability, then the two candidates
PASSPHRASES = ["", "TUESDAY", "BREATHE"]


def derive_address(mnemonic: str, passphrase: str) -> str:
    """Derive the Legacy P2PKH address at m/44'/0'/0'/0/0."""
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


def main() -> None:
    combinations = list(product(*MATRIX))
    total = len(combinations)

    print("=" * 70)
    print("BIP39 Puzzle Solver")
    print("=" * 70)
    print(f"Target Address : {TARGET_ADDRESS}")
    print(f"Derivation Path: m/44'/0'/0'/0/0 (Legacy P2PKH)")
    print(f"Combinations   : {total}")
    print(f"Passphrases    : {PASSPHRASES!r} (empty first)")
    print("=" * 70)

    validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
    valid_count = 0

    for idx, words in enumerate(combinations, start=1):
        mnemonic = " ".join(words)

        # Step 1: checksum validation - skip invalid phrases entirely
        if not validator.IsValid(mnemonic):
            print(f"[{idx:>2}/{total}] [INVALID] {mnemonic}")
            continue

        valid_count += 1

        # Step 2: derive address for each passphrase (empty first)
        for passphrase in PASSPHRASES:
            try:
                address = derive_address(mnemonic, passphrase)
            except Exception as exc:  # graceful handling, never crash
                print(f"[{idx:>2}/{total}] [ERROR]   {mnemonic} | passphrase={passphrase!r} -> {exc}")
                continue

            if address == TARGET_ADDRESS:
                print()
                print("!" * 70)
                print(">>> MATCH FOUND <<<")
                print("!" * 70)
                print(f"Mnemonic  : {mnemonic}")
                print(f"Passphrase: {passphrase!r}")
                print(f"Address   : {address}")
                print("!" * 70)
                sys.exit(0)

            print(
                f"[{idx:>2}/{total}] [VALID CHECKSUM] Phrase: {mnemonic} | "
                f"passphrase={passphrase!r} | Derived: {address}"
            )

    print()
    print("=" * 70)
    print(f"Search complete. {valid_count} valid-checksum phrases tested. No match found.")
    print("=" * 70)


if __name__ == "__main__":
    main()
