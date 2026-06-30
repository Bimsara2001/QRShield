from pymongo import MongoClient

MONGO_URI = "mongodb+srv://pvbimsara0804_db_user:DNNP8oEPeuvcsiMh@qrshieldcluster.gztrjri.mongodb.net/?appName=QRShieldCluster"

client = MongoClient(MONGO_URI)

db = client["qrshield"]

scan_collection = db["scan_history"]