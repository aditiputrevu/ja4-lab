import json
import sys

from database import initialize, insert_observation


def first_value(record, prefix):
    for key, value in record.items():
        if key == prefix or key.startswith(prefix + "."):
            return value

    return None


def normalize_record(record, application, notes=None):
    return {
        "device": "My MacBook",
        "application": application,
        "src": record.get("src"),
        "dst": record.get("dst"),
        "srcport": record.get("srcport"),
        "dstport": record.get("dstport"),
        "domain": record.get("domain"),
        "ja4": first_value(record, "JA4"),
        "ja4h": first_value(record, "JA4H"),
        "ja4s": first_value(record, "JA4S"),
        "notes": notes,
    }


def load_results(filename):
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, dict):
        return [data]

    return data


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: python import_results.py "
            "<results.json> <application>"
        )
        sys.exit(1)

    filename = sys.argv[1]
    application = sys.argv[2]

    initialize()

    records = load_results(filename)
    count = 0

    for record in records:
        observation = normalize_record(
            record,
            application,
            notes=f"{application} controlled capture",
        )

        if (
            observation["ja4"] is None
            and observation["ja4h"] is None
            and observation["ja4s"] is None
        ):
            continue

        insert_observation(observation)
        count += 1

    print(
        f"Imported {count} observations "
        f"for {application}."
    )


if __name__ == "__main__":
    main()