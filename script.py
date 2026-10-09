
def classify_output(script_hex: str) -> str:
    """Identify a standard Bitcoin scriptPubKey."""
    try:
        script = bytes.fromhex(script_hex)
    except ValueError as exc:
        raise ValueError("invalid hexadecimal script") from exc

    # P2PKH: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
    if (
        len(script) == 25
        and script[:3] == bytes.fromhex("76a914")
        and script[-2:] == bytes.fromhex("88ac")
    ):
        return "p2pkh"

    # P2SH: OP_HASH160 PUSH20 <hash> OP_EQUAL
    if (
        len(script) == 23
        and script[:2] == bytes.fromhex("a914")
        and script[-1:] == bytes.fromhex("87")
    ):
        return "p2sh"

    # P2WPKH: OP_0 PUSH20 <hash>
    if len(script) == 22 and script[:2] == bytes.fromhex("0014"):
        return "p2wpkh"

    # P2WSH: OP_0 PUSH32 <hash>
    if len(script) == 34 and script[:2] == bytes.fromhex("0020"):
        return "p2wsh"

    # P2TR: OP_1 PUSH32 <key>
    if len(script) == 34 and script[:2] == bytes.fromhex("5120"):
        return "p2tr"

    # OP_RETURN: provably unspendable output
    if script.startswith(b"\x6a"):
        return "nulldata"

    # P2PK: PUSH33/PUSH65 <public key> OP_CHECKSIG
    if (
        len(script) in (35, 67)
        and script[0] in (33, 65)
        and script[-1] == 0xAC
    ):
        return "p2pk"

    return "unknown"


OPCODES = {
    0x00: "OP_0",
    0x4F: "OP_1NEGATE",
    0x51: "OP_1",
    0x52: "OP_2",
    0x53: "OP_3",
    0x54: "OP_4",
    0x55: "OP_5",
    0x56: "OP_6",
    0x57: "OP_7",
    0x58: "OP_8",
    0x59: "OP_9",
    0x5A: "OP_10",
    0x5B: "OP_11",
    0x5C: "OP_12",
    0x5D: "OP_13",
    0x5E: "OP_14",
    0x5F: "OP_15",
    0x60: "OP_16",
    0x6A: "OP_RETURN",
    0x76: "OP_DUP",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0xA9: "OP_HASH160",
    0xAC: "OP_CHECKSIG",
}


def disassemble_script(script_hex: str) -> list[str]:
    """Convert Bitcoin Script bytes into readable opcodes."""
    try:
        data = bytes.fromhex(script_hex)
    except ValueError as exc:
        raise ValueError("invalid hexadecimal script") from exc

    result = []
    offset = 0

    while offset < len(data):
        opcode = data[offset]
        offset += 1

        if 1 <= opcode <= 75:
            # Direct push of 1-75 bytes.
            size = opcode

        elif opcode == 0x4C:
            # OP_PUSHDATA1: next byte is data length.
            if offset + 1 > len(data):
                raise ValueError("truncated script")
            size = data[offset]
            offset += 1

        elif opcode == 0x4D:
            # OP_PUSHDATA2: next two bytes are length.
            if offset + 2 > len(data):
                raise ValueError("truncated script")
            size = int.from_bytes(
                data[offset:offset + 2], "little"
            )
            offset += 2

        elif opcode == 0x4E:
            # OP_PUSHDATA4: next four bytes are length.
            if offset + 4 > len(data):
                raise ValueError("truncated script")
            size = int.from_bytes(
                data[offset:offset + 4], "little"
            )
            offset += 4

        else:
            result.append(
                OPCODES.get(opcode, f"OP_UNKNOWN_{opcode:02x}")
            )
            continue

        if offset + size > len(data):
            raise ValueError("truncated script")

        pushed = data[offset:offset + size]
        result.append(f"<{pushed.hex()}>")
        offset += size

    return result





import hashlib


BASE58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
)


def base58check_encode(prefix: bytes, payload: bytes) -> str:
    """Encode a Bitcoin address using Base58Check."""
    data = prefix + payload

    checksum = hashlib.sha256(
        hashlib.sha256(data).digest()
    ).digest()[:4]

    full_data = data + checksum

    number = int.from_bytes(full_data, "big")
    encoded = ""

    while number > 0:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    leading_zeros = len(full_data) - len(
        full_data.lstrip(b"\x00")
    )

    return "1" * leading_zeros + encoded




def legacy_address(script_hex: str, network: str = "mainnet") -> str | None:
    """Generate a P2PKH or P2SH Bitcoin address."""
    script_type = classify_output(script_hex)
    script = bytes.fromhex(script_hex)

    if network == "mainnet":
        p2pkh_prefix = b"\x00"
        p2sh_prefix = b"\x05"
    elif network in ("testnet", "regtest"):
        p2pkh_prefix = b"\x6f"
        p2sh_prefix = b"\xc4"
    else:
        raise ValueError("unknown network")

    if script_type == "p2pkh":
        return base58check_encode(p2pkh_prefix, script[3:23])

    if script_type == "p2sh":
        return base58check_encode(p2sh_prefix, script[2:22])

    return None





BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def convertbits(data, frombits=8, tobits=5, pad=True):
    """Convert groups of bits to a different size."""
    acc = 0
    bits = 0
    result = []
    maxv = (1 << tobits) - 1

    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("invalid bit group")

        acc = (acc << frombits) | value
        bits += frombits

        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & maxv)

    if pad and bits:
        result.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or
                      ((acc << (tobits - bits)) & maxv)):
        raise ValueError("invalid padding")

    return result


def bech32_polymod(values):
    """Calculate the Bech32 checksum polynomial."""
    generators = [
        0x3B6A57B2, 0x26508E6D, 0x1EA119FA,
        0x3D4233DD, 0x2A1462B3
    ]
    chk = 1

    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value

        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]

    return chk


def bech32_hrp_expand(hrp):
    return (
        [ord(char) >> 5 for char in hrp]
        + [0]
        + [ord(char) & 31 for char in hrp]
    )


def bech32_encode(hrp, witness_version, program):
    """Encode a SegWit address using Bech32 or Bech32m."""
    if not 0 <= witness_version <= 16:
        raise ValueError("invalid witness version")

    if not 2 <= len(program) <= 40:
        raise ValueError("invalid witness program length")

    if witness_version == 0 and len(program) not in (20, 32):
        raise ValueError("invalid version 0 witness length")

    data = [witness_version] + convertbits(program)

    constant = 1 if witness_version == 0 else 0x2BC830A3

    values = (
        bech32_hrp_expand(hrp)
        + data
        + [0] * 6
    )

    checksum = bech32_polymod(values) ^ constant
    combined = data + [
        (checksum >> (5 * (5 - i))) & 31
        for i in range(6)
    ]

    return hrp + "1" + "".join(
        BECH32_CHARSET[value] for value in combined
    )




def address_for_output(script_hex: str, network: str = "regtest") -> str | None:
    """Return the address for a standard Bitcoin output."""
    script_type = classify_output(script_hex)
    script = bytes.fromhex(script_hex)

    if script_type in ("p2pkh", "p2sh"):
        return legacy_address(script_hex, network)

    if network == "mainnet":
        hrp = "bc"
    elif network == "testnet":
        hrp = "tb"
    elif network == "regtest":
        hrp = "bcrt"
    else:
        raise ValueError("unknown network")

    if script_type == "p2wpkh":
        return bech32_encode(hrp, 0, script[2:])

    if script_type == "p2wsh":
        return bech32_encode(hrp, 0, script[2:])

    if script_type == "p2tr":
        return bech32_encode(hrp, 1, script[2:])

    if script_type == "p2pk":
        # P2PK scripts contain a public key, not its hash.
        # HASH160(pubkey) can be represented as a P2PKH address.
        pubkey = script[1:-1]
        public_key_hash = hashlib.new(
            "ripemd160",
            hashlib.sha256(pubkey).digest()
        ).digest()

        prefix = b"\x00" if network == "mainnet" else b"\x6f"
        return base58check_encode(prefix, public_key_hash)

    return None
