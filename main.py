
import argparse
import json
from pathlib import Path

from parser import (
    calculate_legacy_txid,
    calculate_segwit_metrics,
    detect_segwit,
    parse_legacy_transaction,
    parse_segwit_transaction,
)
from script import (
    address_for_output,
    classify_output,
    disassemble_script,
)


def main():
    arg_parser = argparse.ArgumentParser(
        description="My Bitcoin Transaction Parser"
    )

    arg_parser.add_argument(
        "transaction",
        help="Raw transaction hex or path to a text file"
    )

    args = arg_parser.parse_args()
    value = args.transaction

    if Path(value).is_file():
        raw_hex = Path(value).read_text(
            encoding="utf-8"
        ).strip()
    else:
        raw_hex = value.strip()

    if detect_segwit(raw_hex):
        tx = parse_segwit_transaction(raw_hex)
        metrics = calculate_segwit_metrics(raw_hex)
        tx["segwit"] = True
        tx.update(metrics)
    else:
        tx = parse_legacy_transaction(raw_hex)
        tx["segwit"] = False
        tx["txid"] = calculate_legacy_txid(raw_hex)
        tx["wtxid"] = tx["txid"]
        tx["size"] = len(bytes.fromhex(raw_hex))

    # Add classification, script instructions,
    # and Bitcoin addresses for each output.
    for output in tx["outputs"]:
        script_hex = output["scriptPubKey"]

        output["type"] = classify_output(script_hex)
        output["asm"] = disassemble_script(script_hex)
        output["address"] = address_for_output(
            script_hex,
            network="regtest"
        )

    print(json.dumps(tx, indent=2))


if __name__ == "__main__":
    main()
