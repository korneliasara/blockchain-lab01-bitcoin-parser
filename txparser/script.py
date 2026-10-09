
"""Compatibility functions for Bitcoin Script."""

from script import (
    classify_output,
    disassemble_script,
    address_for_output,
    bech32_encode,
    base58check_encode,
)


def classify(script: bytes):
    """Return the output type and its payload."""
    script_hex = script.hex()
    script_type = classify_output(script_hex)

    if script_type == "p2pkh":
        payload = script[3:23]
    elif script_type == "p2sh":
        payload = script[2:22]
    elif script_type in ("p2wpkh", "p2wsh", "p2tr"):
        payload = script[2:]
    elif script_type == "p2pk":
        payload = script[1:-1]
    else:
        payload = None

    return script_type, payload


def disassemble(script: bytes):
    return disassemble_script(script.hex())


def address_for(script_type, payload, network="regtest"):
    if payload is None:
        return None

    if script_type == "p2pk":
        import hashlib
        payload = hashlib.new(
            "ripemd160",
            hashlib.sha256(payload).digest()
        ).digest()
        script_type = "p2pkh"

    if script_type == "p2pkh":
        from script import base58check_encode
        prefix = b"\x00" if network == "mainnet" else b"\x6f"
        return base58check_encode(prefix, payload)

    if script_type == "p2sh":
        prefix = b"\x05" if network == "mainnet" else b"\xc4"
        return base58check_encode(prefix, payload)

    if script_type in ("p2wpkh", "p2wsh", "p2tr"):
        hrp = {
            "mainnet": "bc",
            "testnet": "tb",
            "regtest": "bcrt",
        }[network]

        version = 1 if script_type == "p2tr" else 0
        return bech32_encode(hrp, version, payload)

    return None
