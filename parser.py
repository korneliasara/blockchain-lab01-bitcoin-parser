
def read_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Read a Bitcoin CompactSize integer.

    Returns:
        (value, number_of_bytes_consumed)
    """
    if offset < 0 or offset >= len(data):
        raise ValueError("truncated CompactSize")

    prefix = data[offset]

    if prefix < 0xFD:
        return prefix, 1

    if prefix == 0xFD:
        length = 2
    elif prefix == 0xFE:
        length = 4
    else:
        length = 8

    end = offset + 1 + length

    if end > len(data):
        raise ValueError("truncated CompactSize")

    value = int.from_bytes(
        data[offset + 1:end],
        byteorder="little"
    )

    return value, 1 + length


def write_compact_size(value: int) -> bytes:
    """Encode an integer using Bitcoin CompactSize."""
    if value < 0 or value >= 2**64:
        raise ValueError("Value outside uint64 range")

    if value < 0xFD:
        return bytes([value])

    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")

    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")

    return b"\xff" + value.to_bytes(8, "little")



class ByteReader:
    """Read binary fields while tracking byte offsets."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("negative read length")

        end = self.offset + length

        if end > len(self.data):
            raise ValueError("truncated transaction")

        result = self.data[self.offset:end]
        self.offset = end
        return result

    def read_uint32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def read_uint64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def read_varint(self) -> int:
        value, consumed = read_compact_size(
            self.data, self.offset
        )
        self.offset += consumed
        return value




def parse_legacy_transaction(raw_hex: str) -> dict:
    """Parse the fields of a legacy Bitcoin transaction."""
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        raise ValueError("invalid hexadecimal transaction")

    reader = ByteReader(data)
    result = {}

    result["version"] = reader.read_uint32()

    input_count = reader.read_varint()
    result["input_count"] = input_count
    result["inputs"] = []

    for _ in range(input_count):
        start_offset = reader.offset

        prev_txid = reader.read(32)[::-1].hex()
        prev_vout = reader.read_uint32()

        script_length = reader.read_varint()
        script_sig = reader.read(script_length).hex()
        sequence = reader.read_uint32()

        result["inputs"].append({
            "offset": start_offset,
            "prev_txid": prev_txid,
            "vout": prev_vout,
            "scriptSig": script_sig,
            "sequence": sequence
        })

    output_count = reader.read_varint()
    result["output_count"] = output_count
    result["outputs"] = []

    for _ in range(output_count):
        start_offset = reader.offset

        value_sat = reader.read_uint64()
        script_length = reader.read_varint()
        script_pubkey = reader.read(script_length).hex()

        result["outputs"].append({
            "offset": start_offset,
            "value_sat": value_sat,
            "scriptPubKey": script_pubkey
        })

    result["locktime"] = reader.read_uint32()

    if reader.offset != len(data):
        raise ValueError("trailing bytes after transaction")

    return result



import hashlib


def double_sha256(data: bytes) -> bytes:
    """Calculate SHA256(SHA256(data))."""
    first_hash = hashlib.sha256(data).digest()
    return hashlib.sha256(first_hash).digest()


def calculate_legacy_txid(raw_hex: str) -> str:
    """Calculate a legacy Bitcoin transaction ID."""
    # Validate that the legacy transaction can be parsed.
    parse_legacy_transaction(raw_hex)

    raw_bytes = bytes.fromhex(raw_hex)

    # Reverse bytes for Bitcoin's displayed txid format.
    return double_sha256(raw_bytes)[::-1].hex()



def detect_segwit(raw_hex: str) -> bool:
    """Detect the SegWit marker and flag."""
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        raise ValueError("invalid hexadecimal transaction")

    if len(data) < 6:
        raise ValueError("truncated transaction")

    # Version occupies the first four bytes.
    # SegWit marker and flag follow.
    return data[4] == 0x00 and data[5] == 0x01




def parse_segwit_transaction(raw_hex: str) -> dict:
    """Parse a Bitcoin SegWit v0 transaction."""
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ValueError("invalid hexadecimal transaction") from exc

    if not detect_segwit(raw_hex):
        raise ValueError("not a SegWit transaction")

    reader = ByteReader(data)
    result = {}

    result["version"] = reader.read_uint32()
    result["marker"] = reader.read(1).hex()
    result["flag"] = reader.read(1).hex()

    input_count = reader.read_varint()
    result["input_count"] = input_count
    result["inputs"] = []

    for _ in range(input_count):
        start = reader.offset

        prev_txid = reader.read(32)[::-1].hex()
        vout = reader.read_uint32()
        script_length = reader.read_varint()
        script_sig = reader.read(script_length).hex()
        sequence = reader.read_uint32()

        result["inputs"].append({
            "offset": start,
            "prev_txid": prev_txid,
            "vout": vout,
            "scriptSig": script_sig,
            "sequence": sequence,
            "witness": []
        })

    output_count = reader.read_varint()
    result["output_count"] = output_count
    result["outputs"] = []

    for _ in range(output_count):
        start = reader.offset

        value_sat = reader.read_uint64()
        script_length = reader.read_varint()
        script_pubkey = reader.read(script_length).hex()

        result["outputs"].append({
            "offset": start,
            "value_sat": value_sat,
            "scriptPubKey": script_pubkey
        })

    # Each input has its own witness stack.
    for tx_input in result["inputs"]:
        item_count = reader.read_varint()

        for _ in range(item_count):
            item_length = reader.read_varint()
            item = reader.read(item_length)

            tx_input["witness"].append(item.hex())

    result["locktime"] = reader.read_uint32()

    if reader.offset != len(data):
        raise ValueError("trailing bytes after transaction")

    result["size"] = len(data)

    return result



def serialize_without_witness(tx: dict) -> bytes:
    """Reconstruct transaction bytes without SegWit data."""
    result = bytearray()

    result += tx["version"].to_bytes(4, "little")

    result += write_compact_size(len(tx["inputs"]))

    for txin in tx["inputs"]:
        result += bytes.fromhex(txin["prev_txid"])[::-1]
        result += txin["vout"].to_bytes(4, "little")

        script = bytes.fromhex(txin["scriptSig"])
        result += write_compact_size(len(script))
        result += script

        result += txin["sequence"].to_bytes(4, "little")

    result += write_compact_size(len(tx["outputs"]))

    for txout in tx["outputs"]:
        result += txout["value_sat"].to_bytes(8, "little")

        script = bytes.fromhex(txout["scriptPubKey"])
        result += write_compact_size(len(script))
        result += script

    result += tx["locktime"].to_bytes(4, "little")

    return bytes(result)


def calculate_segwit_metrics(raw_hex: str) -> dict:
    """Calculate SegWit hashes, weight and virtual size."""
    tx = parse_segwit_transaction(raw_hex)

    full_bytes = bytes.fromhex(raw_hex)
    stripped_bytes = serialize_without_witness(tx)

    txid = double_sha256(stripped_bytes)[::-1].hex()
    wtxid = double_sha256(full_bytes)[::-1].hex()

    total_size = len(full_bytes)
    stripped_size = len(stripped_bytes)

    weight = 3 * stripped_size + total_size
    vsize = (weight + 3) // 4

    return {
        "txid": txid,
        "wtxid": wtxid,
        "size": total_size,
        "stripped_size": stripped_size,
        "weight": weight,
        "vsize": vsize,
    }



def serialize_transaction(tx: dict) -> bytes:
    """Reconstruct a legacy or SegWit transaction."""

    base = serialize_without_witness(tx)

    # Legacy transactions are already complete.
    if "marker" not in tx:
        return base

    # SegWit: insert marker/flag after version,
    # and witness stacks before locktime.
    result = bytearray()

    result += base[:4]
    result += bytes.fromhex(tx["marker"])
    result += bytes.fromhex(tx["flag"])

    # Base transaction excluding version and locktime.
    result += base[4:-4]

    for txin in tx["inputs"]:
        witness = txin["witness"]

        result += write_compact_size(len(witness))

        for item_hex in witness:
            item = bytes.fromhex(item_hex)

            result += write_compact_size(len(item))
            result += item

    result += base[-4:]

    return bytes(result)

