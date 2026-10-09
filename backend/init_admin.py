import os
import sys

from pymongo import MongoClient
from werkzeug.security import generate_password_hash

from app.config import Config


def main():
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")
    email = os.getenv("ADMIN_EMAIL", "").strip()
    if not username or not password:
        print("ADMIN_USERNAME and ADMIN_PASSWORD are required.", file=sys.stderr)
        return 2
    client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=Config.MONGO_CONNECT_TIMEOUT_MS)
    users = client.get_default_database().users
    users.create_index("username", unique=True)
    if users.find_one({"username": username}, {"_id": 1}):
        print(f'Administrator "{username}" already exists.')
        return 0
    users.insert_one({
        "username": username,
        "password": generate_password_hash(password, method="pbkdf2:sha256", salt_length=24),
        "email": email,
        "firstname": "",
        "lastname": "",
        "role": 0,
        "rights": {"delete_record": True, "register_user": True},
    })
    print(f'Administrator "{username}" created.')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
