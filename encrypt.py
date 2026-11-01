#!/usr/bin/env python3
"""
encrypt.py — re-encrypt LABS content files

Usage:
    python3 encrypt.py "/path/to/LABS Content"  # encrypt files in place
    python3 encrypt.py "/path/to/LABS Content" --output "/path/to/output"  # optional output folder
    python3 encrypt.py "/path/to/LABS Content" --key <hex>      # use a specific key instead of the key stored at machine-key.key
"""
import argparse
import json
import os
import sys

import labs_blowfish as L
import utils

def main():
    ap = argparse.ArgumentParser(description="Re-encrypt LABS content files")
    ap.add_argument("root", nargs="?", help=f"content folder to process")
    ap.add_argument("--output", help=f"content folder to export decrypted files")
    ap.add_argument("--key", help="Machine key hex to use (default: read from machine-key.key file)")
    args = ap.parse_args()

    try:
        key = utils.parse_key(args.key) if args.key else utils.get_machine_key()
    except Exception as e:
        print(f"bad key: {e}"); return 2
    if len(key) == 0:
        print("no key set"); return 2

    if args.root is None or args.root == "":
        print("no root folder set. Use -h for help"); return 2
    if not os.path.isdir(args.root):
        print(f"content folder not found: {args.root}"); return 2

    if args.output is None:
        args.output = args.root

    print(f"Root: {args.root}")
    print(f"Output: {args.output}")
    print(f"Key: {key.hex()[:16]}...\n")

    done = already = skipped = 0
    for path in utils.iter_content_files(args.root):
        rel = os.path.relpath(path, args.root)
        output_path = os.path.join(args.output, rel)
        print("  encrypting  ", rel)
        raw = open(path, "rb").read()

        if L.is_encrypted(raw):
            already += 1
            if output_path != path:
                utils.write_bytes_to_file(output_path, raw)
            continue  # already encrypted

        if not utils.looks_like_json(raw):
            print(f"  SKIP  {rel}  (doesn't look like JSON plaintext)")
            skipped += 1
            continue

        enc = L.encrypt_bytes(raw, key)
        utils.write_bytes_to_file(output_path, enc)
        done += 1

    print(f"\nEncrypted: {done}   already-encrypted: {already}   skipped: {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
