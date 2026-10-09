
"""Compatibility functions for the Bitcoin parser."""

from parser import (
    read_compact_size,
    write_compact_size,
    parse_legacy_transaction,
    parse_segwit_transaction,
    serialize_transaction,
    calculate_legacy_txid,
    calculate_segwit_metrics,
    detect_segwit,
    double_sha256,
    ByteReader,
)


def hash160(data: bytes) -> bytes:
    """Calculate RIPEMD160(SHA256(data))."""
    import hashlib

    sha_hash = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha_hash).digest()



from dataclasses import dataclass, field


@dataclass
class TxInput:
    prev_txid: bytes
    prev_vout: int
    script_sig: bytes
    sequence: int
    witness: list[bytes] = field(default_factory=list)

    @property
    def is_coinbase(self) -> bool:
        return (
            self.prev_txid == b"\x00" * 32
            and self.prev_vout == 0xFFFFFFFF
        )


@dataclass
class TxOutput:
    value_sat: int
    script_pubkey: bytes

    @property
    def value_btc(self) -> str:
        return f"{self.value_sat / 100_000_000:.8f}"


@dataclass
class Transaction:
    version: int
    inputs: list[TxInput]
    outputs: list[TxOutput]
    locktime: int
    is_segwit: bool
    txid: str
    wtxid: str
    size: int
    stripped_size: int
    weight: int
    vsize: int

    @property
    def total_output_sat(self) -> int:
        return sum(output.value_sat for output in self.outputs)

    def serialise(self, include_witness=True) -> bytes:
        data = {
            "version": self.version,
            "inputs": [
                {
                    "prev_txid": txin.prev_txid.hex(),
                    "vout": txin.prev_vout,
                    "scriptSig": txin.script_sig.hex(),
                    "sequence": txin.sequence,
                    "witness": [
                        item.hex() for item in txin.witness
                    ],
                }
                for txin in self.inputs
            ],
            "outputs": [
                {
                    "value_sat": txout.value_sat,
                    "scriptPubKey": txout.script_pubkey.hex(),
                }
                for txout in self.outputs
            ],
            "locktime": self.locktime,
        }

        if self.is_segwit and include_witness:
            data["marker"] = "00"
            data["flag"] = "01"

        return serialize_transaction(data)


def parse_hex(raw_hex: str) -> Transaction:
    """Parse raw Bitcoin hex into a transaction object."""
    if detect_segwit(raw_hex):
        parsed = parse_segwit_transaction(raw_hex)
        metrics = calculate_segwit_metrics(raw_hex)
        segwit = True
    else:
        parsed = parse_legacy_transaction(raw_hex)
        txid = calculate_legacy_txid(raw_hex)
        raw_size = len(bytes.fromhex(raw_hex))

        metrics = {
            "txid": txid,
            "wtxid": txid,
            "size": raw_size,
            "stripped_size": raw_size,
            "weight": raw_size * 4,
            "vsize": raw_size,
        }
        segwit = False

    inputs = [
        TxInput(
            prev_txid=bytes.fromhex(item["prev_txid"]),
            prev_vout=item["vout"],
            script_sig=bytes.fromhex(item["scriptSig"]),
            sequence=item["sequence"],
            witness=[
                bytes.fromhex(w) for w in item.get("witness", [])
            ],
        )
        for item in parsed["inputs"]
    ]

    outputs = [
        TxOutput(
            value_sat=item["value_sat"],
            script_pubkey=bytes.fromhex(item["scriptPubKey"]),
        )
        for item in parsed["outputs"]
    ]

    return Transaction(
        version=parsed["version"],
        inputs=inputs,
        outputs=outputs,
        locktime=parsed["locktime"],
        is_segwit=segwit,
        **metrics,
    )
