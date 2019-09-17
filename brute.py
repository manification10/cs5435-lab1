from csv import reader
import hashlib, binascii
from app.util.hash import hash_pbkdf2

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

def brute_force_attack(target_hash, target_salt):
    common_passwords = load_common_passwords()
    for password in common_passwords:
        resulting_hash = hash_pbkdf2(password[0], target_salt)
        if target_hash == resulting_hash:
            return password[0]
    return None

def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    for salted_cred in salted_creds:
        print(salted_cred[2])
        password = brute_force_attack(salted_cred[1], salted_cred[2])
        print(password)

if __name__ == "__main__":
    main()
