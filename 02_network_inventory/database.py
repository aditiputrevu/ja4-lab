import sqlite3


DATABASE = "fingerprints.db"


def connect():
    return sqlite3.connect(DATABASE)


def initialize():
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        device TEXT,
        application TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port TEXT,
        dst_port TEXT,
        domain TEXT,
        ja4 TEXT,
        ja4h TEXT,
        ja4s TEXT,
        notes TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_observation(observation):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO observations (
            device,
            application,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            domain,
            ja4,
            ja4h,
            ja4s,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        observation.get("device"),
        observation.get("application"),
        observation.get("src"),
        observation.get("dst"),
        observation.get("srcport"),
        observation.get("dstport"),
        observation.get("domain"),
        observation.get("ja4"),
        observation.get("ja4h"),
        observation.get("ja4s"),
        observation.get("notes"),
    ))

    conn.commit()
    conn.close()


if __name__ == "__main__":
    initialize()
    print("Database initialized.")