
import pytest

from parser import read_compact_size, write_compact_size


@pytest.mark.parametrize("value,expected_length", [
    (0, 1),
    (252, 1),
    (253, 3),
    (65535, 3),
    (65536, 5),
    (2**32 - 1, 5),
    (2**32, 9),
])
def test_compact_size_roundtrip(value, expected_length):
    encoded = write_compact_size(value)

    assert len(encoded) == expected_length

    decoded, consumed = read_compact_size(encoded)

    assert decoded == value
    assert consumed == expected_length


def test_nonzero_offset():
    data = b"\xaa\xbb" + write_compact_size(300)

    value, consumed = read_compact_size(data, 2)

    assert value == 300
    assert consumed == 3


def test_truncated_data():
    with pytest.raises(ValueError, match="truncated"):
        read_compact_size(b"\xfd\x01")




from parser import ByteReader


def test_byte_reader():
    data = bytes.fromhex("0200000001")

    reader = ByteReader(data)

    assert reader.read_uint32() == 2
    assert reader.offset == 4

    assert reader.read_varint() == 1
    assert reader.offset == 5


def test_byte_reader_truncated():
    reader = ByteReader(bytes.fromhex("0200"))

    with pytest.raises(ValueError, match="truncated"):
        reader.read_uint32()


def test_byte_reader_uint64():
    reader = ByteReader(
        (5_000_000_000).to_bytes(8, "little")
    )

    assert reader.read_uint64() == 5_000_000_000
    assert reader.offset == 8




from parser import parse_legacy_transaction


def test_legacy_transaction_fields():
    raw = (
        "02000000"                 # Version 2
        "01"                       # One input
        + "11" * 32                # Previous txid
        + "00000000"               # vout = 0
        + "00"                     # Empty scriptSig
        + "ffffffff"               # Sequence
        + "01"                     # One output
        + "00e1f50500000000"       # 1 BTC in satoshis
        + "00"                     # Empty scriptPubKey
        + "00000000"               # Locktime
    )

    tx = parse_legacy_transaction(raw)

    assert tx["version"] == 2
    assert tx["input_count"] == 1
    assert tx["output_count"] == 1
    assert tx["inputs"][0]["offset"] == 5
    assert tx["inputs"][0]["vout"] == 0
    assert tx["outputs"][0]["value_sat"] == 100_000_000
    assert tx["locktime"] == 0



from parser import calculate_legacy_txid


def test_double_sha256_txid():
    raw = (
        "02000000"
        "01"
        + "11" * 32
        + "00000000"
        + "00"
        + "ffffffff"
        + "01"
        + "00e1f50500000000"
        + "00"
        + "00000000"
    )

    txid = calculate_legacy_txid(raw)

    assert len(txid) == 64
    assert len(bytes.fromhex(txid)) == 32


def test_invalid_transaction_rejected():
    import pytest

    with pytest.raises(ValueError):
        calculate_legacy_txid("abcd")



# Bitcoin genesis block coinbase transaction
GENESIS_COINBASE = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368"
    "616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066"
    "6f722062616e6b73ffffffff0100f2052a0100000043410467"
    "8afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef"
    "38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)

GENESIS_TXID = (
    "4a5e1e4baab89f3a32518a88c31bc87f"
    "618f76673e2cc77ab2127b7afdeda33b"
)


def test_genesis_transaction():
    tx = parse_legacy_transaction(GENESIS_COINBASE)

    assert tx["version"] == 1
    assert tx["input_count"] == 1
    assert tx["output_count"] == 1
    assert tx["inputs"][0]["offset"] == 5
    assert tx["outputs"][0]["value_sat"] == 5_000_000_000
    assert tx["locktime"] == 0


def test_genesis_transaction_id():
    calculated = calculate_legacy_txid(GENESIS_COINBASE)

    assert calculated == GENESIS_TXID


def test_genesis_coinbase_input():
    tx = parse_legacy_transaction(GENESIS_COINBASE)

    assert tx["inputs"][0]["prev_txid"] == "00" * 32
    assert tx["inputs"][0]["vout"] == 0xFFFFFFFF

    script = bytes.fromhex(tx["inputs"][0]["scriptSig"])

    assert b"Chancellor on brink of second bailout for banks" in script




# First person-to-person Bitcoin payment, block 170
FIRST_PAYMENT = (
    "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704"
    "000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548"
    "ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d"
    "1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f715"
    "9b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1bade"
    "d5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1e"
    "b68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4"
    "c03f999b8643f656b412a3ac00000000"
)

FIRST_PAYMENT_TXID = (
    "f4184fc596403b9d638783cf57adfe4c"
    "75c605f6356fbc91338530e9831e9e16"
)


def test_first_payment_fields():
    tx = parse_legacy_transaction(FIRST_PAYMENT)

    assert tx["version"] == 1
    assert tx["input_count"] == 1
    assert tx["output_count"] == 2
    assert tx["inputs"][0]["offset"] == 5

    assert tx["outputs"][0]["value_sat"] == 1_000_000_000
    assert tx["outputs"][1]["value_sat"] == 4_000_000_000

    assert tx["locktime"] == 0


def test_first_payment_txid():
    assert calculate_legacy_txid(FIRST_PAYMENT) == FIRST_PAYMENT_TXID


def test_first_payment_total_outputs():
    tx = parse_legacy_transaction(FIRST_PAYMENT)

    total = sum(
        output["value_sat"] for output in tx["outputs"]
    )

    assert total == 5_000_000_000




from parser import detect_segwit


def test_genesis_is_not_segwit():
    assert detect_segwit(GENESIS_COINBASE) is False


def test_first_payment_is_not_segwit():
    assert detect_segwit(FIRST_PAYMENT) is False


def test_segwit_marker_and_flag():
    # Minimal header for marker/flag detection.
    raw = "020000000001"

    assert detect_segwit(raw) is True


def test_truncated_segwit_header():
    with pytest.raises(ValueError, match="truncated"):
        detect_segwit("02000000")



from pathlib import Path

from parser import parse_segwit_transaction


def get_part_b_transaction():
    path = (
        Path(__file__).resolve().parent.parent
        / "partB-signed-transaction.txt"
    )

    return path.read_text(encoding="utf-8").strip()


def test_part_b_segwit_fields():
    raw = get_part_b_transaction()
    tx = parse_segwit_transaction(raw)

    assert tx["version"] == 2
    assert tx["marker"] == "00"
    assert tx["flag"] == "01"
    assert tx["input_count"] == 1
    assert tx["output_count"] == 2
    assert tx["inputs"][0]["offset"] == 7


def test_part_b_outputs():
    tx = parse_segwit_transaction(get_part_b_transaction())

    assert tx["outputs"][0]["value_sat"] == 1_000_000_000
    assert tx["outputs"][1]["value_sat"] == 3_999_990_000


def test_part_b_witness():
    tx = parse_segwit_transaction(get_part_b_transaction())

    witness = tx["inputs"][0]["witness"]

    assert len(witness) == 2
    assert len(bytes.fromhex(witness[1])) == 33


def test_part_b_size():
    tx = parse_segwit_transaction(get_part_b_transaction())

    assert tx["size"] == 222
    assert tx["locktime"] == 0



from parser import calculate_segwit_metrics


def test_part_b_txid():
    metrics = calculate_segwit_metrics(
        get_part_b_transaction()
    )

    assert metrics["txid"] == (
        "2a6d10cdfab21133f58d25022e58b1bc"
        "db65a5a73626e963bdd5596f35d21407"
    )


def test_part_b_wtxid():
    metrics = calculate_segwit_metrics(
        get_part_b_transaction()
    )

    assert metrics["wtxid"] == (
        "a70b1819be969bc49cd59ca00a9dab7"
        "cd16f288f2bc56cde6506f18c74cf0a8a"
    )


def test_part_b_weight_and_vsize():
    metrics = calculate_segwit_metrics(
        get_part_b_transaction()
    )

    assert metrics["size"] == 222
    assert metrics["stripped_size"] == 113
    assert metrics["weight"] == 561
    assert metrics["vsize"] == 141


from parser import serialize_transaction


def test_genesis_roundtrip():
    tx = parse_legacy_transaction(GENESIS_COINBASE)

    reconstructed = serialize_transaction(tx)

    assert reconstructed.hex() == GENESIS_COINBASE


def test_first_payment_roundtrip():
    tx = parse_legacy_transaction(FIRST_PAYMENT)

    reconstructed = serialize_transaction(tx)

    assert reconstructed.hex() == FIRST_PAYMENT


def test_part_b_segwit_roundtrip():
    raw_hex = get_part_b_transaction()

    tx = parse_segwit_transaction(raw_hex)

    reconstructed = serialize_transaction(tx)

    assert reconstructed.hex() == raw_hex





from script import classify_output


@pytest.mark.parametrize("script_hex,expected", [
    ("76a914" + "11" * 20 + "88ac", "p2pkh"),
    ("a914" + "22" * 20 + "87", "p2sh"),
    ("0014" + "33" * 20, "p2wpkh"),
    ("0020" + "44" * 32, "p2wsh"),
    ("5120" + "55" * 32, "p2tr"),
    ("6a0548656c6c6f", "nulldata"),
    ("21" + "02" + "66" * 32 + "ac", "p2pk"),
])
def test_output_classification(script_hex, expected):
    assert classify_output(script_hex) == expected


def test_genesis_output_classification():
    tx = parse_legacy_transaction(GENESIS_COINBASE)

    script_hex = tx["outputs"][0]["scriptPubKey"]

    assert classify_output(script_hex) == "p2pk"


def test_part_b_output_classification():
    tx = parse_segwit_transaction(
        get_part_b_transaction()
    )

    assert classify_output(tx["outputs"][0]["scriptPubKey"]) == "p2wpkh"
    assert classify_output(tx["outputs"][1]["scriptPubKey"]) == "p2wpkh"


def test_invalid_script_hex():
    with pytest.raises(ValueError, match="hexadecimal"):
        classify_output("not-hex")



from script import disassemble_script


def test_p2pkh_disassembly():
    script = "76a914" + "11" * 20 + "88ac"

    result = disassemble_script(script)

    assert result == [
        "OP_DUP",
        "OP_HASH160",
        "<" + "11" * 20 + ">",
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]


def test_p2wpkh_disassembly():
    script = "0014" + "22" * 20

    assert disassemble_script(script) == [
        "OP_0",
        "<" + "22" * 20 + ">",
    ]


def test_nulldata_disassembly():
    script = "6a0548656c6c6f"

    assert disassemble_script(script) == [
        "OP_RETURN",
        "<48656c6c6f>",
    ]


def test_truncated_pushdata():
    # Requests 5 bytes but only provides 2.
    with pytest.raises(ValueError, match="truncated"):
        disassemble_script("05aabb")


def test_genesis_script_disassembly():
    tx = parse_legacy_transaction(GENESIS_COINBASE)
    script = tx["outputs"][0]["scriptPubKey"]

    result = disassemble_script(script)

    assert len(result) == 2
    assert result[-1] == "OP_CHECKSIG"
    assert result[0].startswith("<04")




def test_legacy_truncated_transaction():
    raw = GENESIS_COINBASE[:-10]

    with pytest.raises(ValueError, match="truncated"):
        parse_legacy_transaction(raw)


def test_legacy_trailing_bytes():
    raw = GENESIS_COINBASE + "deadbeef"

    with pytest.raises(ValueError, match="trailing"):
        parse_legacy_transaction(raw)


def test_segwit_truncated_transaction():
    raw = get_part_b_transaction()[:-10]

    with pytest.raises(ValueError, match="truncated"):
        parse_segwit_transaction(raw)


def test_segwit_trailing_bytes():
    raw = get_part_b_transaction() + "deadbeef"

    with pytest.raises(ValueError, match="trailing"):
        parse_segwit_transaction(raw)
