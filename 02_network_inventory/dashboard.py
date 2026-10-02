import sqlite3

import pandas as pd
import streamlit as st


DATABASE = "fingerprints.db"

st.set_page_config(
    page_title="JA4 Network Inventory",
    layout="wide",
)

st.title("JA4 Network Fingerprint Inventory")

st.write(
    "A local inventory of JA4-family fingerprints "
    "observed in authorized network captures."
)

conn = sqlite3.connect(DATABASE)

df = pd.read_sql_query(
    """
    SELECT *
    FROM observations
    ORDER BY timestamp DESC
    """,
    conn,
)

conn.close()

if df.empty:
    st.warning("No observations have been imported yet.")
    st.stop()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Observations", len(df))

col2.metric(
    "Unique JA4",
    df["ja4"].dropna().nunique(),
)

col3.metric(
    "Domains",
    df["domain"].dropna().nunique(),
)

col4.metric(
    "Devices",
    df["device"].dropna().nunique(),
)

st.subheader("Observed Traffic")

st.dataframe(
    df,
    use_container_width=True,
)

st.subheader("Most Common JA4 Fingerprints")

ja4_counts = (
    df["ja4"]
    .dropna()
    .value_counts()
    .reset_index()
)

ja4_counts.columns = ["JA4", "Count"]

st.dataframe(
    ja4_counts,
    use_container_width=True,
)

st.subheader("Domains")

domain_counts = (
    df["domain"]
    .dropna()
    .value_counts()
    .reset_index()
)

domain_counts.columns = [
    "Domain",
    "Count",
]

st.dataframe(
    domain_counts,
    use_container_width=True,
)

st.subheader("Fingerprints by Application")

app_counts = (
    df
    .dropna(subset=["application", "ja4"])
    .groupby(["application", "ja4"])
    .size()
    .reset_index(name="count")
)

st.dataframe(
    app_counts,
    use_container_width=True,
)