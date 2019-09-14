
from hash import hash_sha256
import os.path
from pathlib import Path
import json

COMMON_PASSWORDS = "common_passwords.txt"
HASHED_PASSWORDS = "common_passwords_lookup_table.json"

def load_passwords(fp):
    base_path = Path(__file__).parent.parent.parent
    path = os.path.join(base_path, fp)
    common_passwords = open(path, "r")
    password_list = []
    for password in common_passwords:
        password_list.append(password.strip())
    return password_list

def build_lookup_table(passwords):
    lookup_table = {}
    for password in passwords:
        lookup_table[hash_sha256(password)] = password
    lookup_table_json = json.dumps(lookup_table)
    f = open(HASHED_PASSWORDS, "w")
    f.write(lookup_table_json)
    f.close()

def main():
    passwords = load_passwords(COMMON_PASSWORDS)
    build_lookup_table(passwords)


if __name__ == "__main__":
    main()
