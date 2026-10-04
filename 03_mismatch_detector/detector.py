import sqlite3
from pathlib import Path


DATABASE = (
    Path(__file__).resolve().parent
    / "../02_network_inventory/fingerprints.db"
).resolve()


def get_header(headers, wanted_name):

    wanted_name = wanted_name.lower()

    for name, value in headers:

        if name.lower() == wanted_name:
            return value

    return None


def classify_user_agent(user_agent):

    if not user_agent:
        return "unknown"

    ua = user_agent.lower()

    if "python-requests" in ua:
        return "python"

    if "curl/" in ua:
        return "curl"

    if "firefox/" in ua:
        return "firefox"

    if (
        "chrome/" in ua
        and "chromium/" not in ua
    ):
        return "chrome"

    if "safari/" in ua and "chrome/" not in ua:
        return "safari"

    return "unknown"


def lookup_ja4_application(ja4):

    if not DATABASE.exists():
        return None

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT application, COUNT(*) AS count
        FROM observations
        WHERE ja4 = ?
        AND application IS NOT NULL
        GROUP BY application
        ORDER BY count DESC
        LIMIT 1
        """,
        (ja4,)
    )

    row = cursor.fetchone()

    conn.close()

    if row:
        return row[0]

    return None


def chrome_header_signals(headers):

    names = [
        name.lower()
        for name, _ in headers
    ]

    expected = [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
    ]

    present = [
        header
        for header in expected
        if header in names
    ]

    score = len(present)

    return {
        "expected_count": len(expected),
        "present_count": score,
        "present": present,
    }


def detect_mismatch(
    headers,
    ja4,
    ja4h
):

    user_agent = get_header(
        headers,
        "user-agent"
    )

    claimed_client = (
        classify_user_agent(
            user_agent
        )
    )

    observed_client = (
        lookup_ja4_application(
            ja4["fingerprint"]
        )
    )

    reasons = []
    score = 0

    # -------------------------------
    # Signal 1:
    # User-Agent vs known JA4
    # -------------------------------

    if (
        claimed_client == "chrome"
        and observed_client
    ):

        observed_lower = (
            observed_client.lower()
        )

        if (
            "curl" in observed_lower
            or "python" in observed_lower
        ):

            score += 60

            reasons.append(
                "User-Agent claims Chrome, "
                f"but JA4 was previously observed "
                f"with {observed_client}."
            )

    # -------------------------------
    # Signal 2:
    # Chrome header characteristics
    # -------------------------------

    if claimed_client == "chrome":

        header_info = (
            chrome_header_signals(
                headers
            )
        )

        if (
            header_info["present_count"]
            < 4
        ):

            score += 30

            reasons.append(
                "Chrome User-Agent has very few "
                "typical Chrome browser headers."
            )

    # -------------------------------
    # Signal 3:
    # suspiciously small HTTP profile
    # -------------------------------

    if (
        claimed_client == "chrome"
        and ja4h["header_count"] <= 5
    ):

        score += 20

        reasons.append(
            "JA4H-style HTTP profile contains "
            "an unusually small header set "
            "for a Chrome request."
        )

    suspicious = score >= 50

    return {
        "suspicious": suspicious,
        "score": min(score, 100),

        "user_agent": user_agent,

        "claimed_client": claimed_client,

        "observed_client": (
            observed_client
        ),

        "ja4": (
            ja4["fingerprint"]
        ),

        "ja4h": (
            ja4h["fingerprint"]
        ),

        "reasons": reasons,
    }