from pymongo import MongoClient
import os

MONGO_URI = os.environ.get("MONGO_URI", "").strip()

client = MongoClient(MONGO_URI) if MONGO_URI else None

db = client["qrshield"] if client is not None else None

scan_collection = db["scan_history"] if db is not None else None
