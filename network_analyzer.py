                
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sqlite3


# CSV file load kar rahe hain

df = pd.read_csv("PROJECT TABLES/network_data.csv")

print("\n===== First 5 Rows =====")
print(df.head())

# Duplicate rows hata rahe hain

df = df.drop_duplicates()

# Missing values fill kar rahe hain

df = df.fillna(0)

print("\nTotal Records :", len(df))

# Average packet size nikal rahe hain
avg_packet = df["packet_size"].mean()

print("Average Packet Size :", avg_packet)


# Simple anomaly detection
# Agar packet size average se 2 guna zyada hai
# to usko High Risk maanenge

risk_list = []

for value in df["packet_size"]:
    if value > avg_packet * 2:
        risk_list.append("High")
    elif value > avg_packet * 1.2:
        risk_list.append("Medium")
    else:
        risk_list.append("Normal")

df["Risk_Level"] = risk_list


# SQLite database bana rahe hain
conn = sqlite3.connect("anomalies.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS anomalies(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    packet_size REAL,
    risk_level TEXT
)
""")

# Sirf High Risk records save karenge

for _, row in df.iterrows():

    if row["Risk_Level"] == "High":

        cursor.execute("""
        INSERT INTO anomalies
        (source_ip,destination_ip,protocol,packet_size,risk_level)

        VALUES(?,?,?,?,?)
        """, (

            row["source_ip"],
            row["destination_ip"],
            row["protocol"],
            row["packet_size"],
            row["Risk_Level"]

        ))

conn.commit()

print("\nHigh Risk Records Saved Successfully!")


# Top protocols count

print("\nProtocol Count")
print(df["protocol"].value_counts())


# Packet Size Histogram

plt.figure(figsize=(7,5))
plt.hist(df["packet_size"], bins=20)
plt.title("Packet Size Distribution")
plt.xlabel("Packet Size")
plt.ylabel("Frequency")
plt.show()


# Risk Level Count

print("\nRisk Summary")
print(df["Risk_Level"].value_counts())


# Final report CSV save kar rahe hain

df.to_csv("final_report.csv", index=False)

print("\nReport Saved : final_report.csv")

conn.close()
