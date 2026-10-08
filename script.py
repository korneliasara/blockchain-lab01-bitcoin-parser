
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

