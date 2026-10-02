import json

from database import initialize, insert_observation


def first_value(record, prefix):
    for key, value in record.items():
        if key == prefix or key.startswith(prefix + "."):
            return value

    return None


def normalize_record(record):
    return {
        "device": "My MacBook",
        "application": "Chrome",
        "src": record.get("src"),
        "dst": record.get("dst"),
        "srcport": record.get("srcport"),
        "dstport": record.get("dstport"),
        "domain": record.get("domain"),
        "ja4": first_value(record, "JA4"),
        "ja4h": first_value(record, "JA4H"),
        "ja4s": first_value(record, "JA4S"),
        "notes": "Chrome test capture",
    }


def load_results(filename):
    with open(
        filename,
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    if isinstance(data, dict):
        return [data]

    return data


def main():
    initialize()

    records = load_results("results.json")

    count = 0

    for record in records:
        observation = normalize_record(record)

        if (
            observation["ja4"] is None
            and observation["ja4h"] is None
            and observation["ja4s"] is None
        ):
            continue

        insert_observation(observation)
        count += 1

    print(
        f"Imported {count} fingerprint observations."
    )


if __name__ == "__main__":
    main()