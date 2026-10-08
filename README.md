Blockchain Lab 01 — Bitcoin Transaction Parser

A Python implementation of a raw Bitcoin transaction parser developed for Blockchain Lab 01.

Features
- Legacy and SegWit transaction parsing
- CompactSize (VarInt) encoding and decoding
- Transaction inputs, outputs, and byte offsets
- Transaction ID (txid) and witness transaction ID (wtxid)
- Transaction weight and virtual size calculations
- Round-trip transaction serialization
- Bitcoin Script disassembly
- Output classification: P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, and nulldata
- Malformed transaction detection

Requirements
- Python 3.11 or newer
- pytest for running tests

Usage
Run the transaction parser from the project folder:
    python main.py transaction.txt

The input can be a file containing raw transaction hexadecimal data or a hexadecimal string.

Running tests
Install pytest:
    python -m pip install pytest

Run the tests:
    python -m pytest -v

Verification
The implementation was tested against:
- Bitcoin's genesis coinbase transaction
- The first Bitcoin payment in block 170
- A SegWit transaction created using Bitcoin Core in regtest mode

54 automated tests passed during development.

Project files
- main.py — Command-line interface
- parser.py — Transaction parsing, serialization, and hashing
- script.py — Script classification and disassembly
- test_parser.py — Automated tests

Course
Introduction to Blockchain Programming — Lab 01