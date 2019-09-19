from sqlalchemy import Column, Integer, String
from app.models.base import Base
from app.util.hash import hash_pbkdf2
import json
from csv import reader

COMMON_PASSWORDS_LOOKUP_TABLE_PATH = "common_passwords_lookup_table.json"
COMMON_PASSWORDS_PATH = 'common_passwords.txt'

class PlaintextBreach(Base):
    __tablename__ = "plaintext_breaches"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    password = Column(String)

class HashedBreach(Base):
    __tablename__ = "hashed_breaches"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    hashed_password = Column(String)

class SaltedBreach(Base):
    __tablename__ = "salted_breaches"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    salted_password = Column(String)
    salt = Column(String)

def create_plaintext_breach_entry(db, username, password):
    breach = PlaintextBreach(
        username=username,
        password=password,
    )
    db.add(breach)
    return breach

def create_hashed_breach_entry(db, username, hashed_password):
    breach = HashedBreach(
        username=username,
        hashed_password=hashed_password,
    )
    db.add(breach)
    return breach

def create_salted_breach_entry(db, username, salted_password, salt):
    breach = SaltedBreach(
        username=username,
        salted_password=salted_password,
        salt=salt,
    )
    db.add(breach)
    return breach

def get_lookup_table():
    with open(COMMON_PASSWORDS_LOOKUP_TABLE_PATH) as json_file:
        hashes = json.load(json_file)
    return hashes

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

def get_passwords_from_breaches(db, username):
    breaches = get_breaches(db, username)
    plaintext_breaches = breaches[0]
    hashed_breaches = breaches[1]
    salted_breaches = breaches[2]
    breached_passwords = []
    print("password from breaches",username)
    print("breaches*****",breaches)
    for breach in plaintext_breaches:
        breached_passwords.append(breach.password)
    for breach in hashed_breaches:
        hash_dict = get_lookup_table()
        breached_passwords.append(hash_dict[breach.hashed_password])
    for breach in salted_breaches:
        salt_password = brute_force_attack(breach.salted_password, breach.salt)
        if salt_password:
            breached_passwords.append(salt_password)
    return breached_passwords

def get_breaches(db, username):
    plaintext_breaches = db.query(PlaintextBreach).filter_by(username=username).all()
    hashed_breaches = db.query(HashedBreach).filter_by(username=username).all()
    salted_breaches = db.query(SaltedBreach).filter_by(username=username).all()
    return (plaintext_breaches, hashed_breaches, salted_breaches)
