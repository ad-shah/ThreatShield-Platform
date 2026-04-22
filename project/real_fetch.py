import requests
from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_db"]
collection = db["real_threats"]

# Real threat feed (CSV format)
url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

response = requests.get(url)

if response.status_code == 200:
    lines = response.text.split("\n")

    for line in lines:
        if line.startswith("#") or line.strip() == "":
            continue

        parts = line.split(",")
        ip = parts[1]

        threat = {
            "ip": ip,
            "type": "malware",
            "source": "abuse.ch",
            "risk": "high"
        }

        # Avoid duplicate
        if not collection.find_one({"ip": ip}):
            collection.insert_one(threat)
            print(f"Inserted: {ip}")

    print("Real threat data stored!")

else:
    print("Error:", response.status_code)
