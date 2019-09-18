from sqlalchemy import Column, Integer, String
from app.models.base import Base
import json

COMMON_PASSWORDS_LOOKUP_TABLE_PATH = "common_passwords_lookup_table.json"

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

def get_passwords_from_breaches(db, username):
    breaches = get_breaches(db, username)
    plaintext_breaches = breaches[0]
    hashed_breaches = breaches[1]
    salted_breaches = breaches[2]
    breached_passwords = []
    for breach in plaintext_breaches:
        breached_passwords.append(breach.password)
    for breach in hashed_breaches:
        hash_dict = get_lookup_table()
        breached_passwords.append(hash_dict[breach.hashed_password])
    for breach in salted_breaches:
        breached_passwords.append(breach.salted_password)
    return breached_passwords

def get_breaches(db, username):
    plaintext_breaches = db.query(PlaintextBreach).filter_by(username=username).all()
    hashed_breaches = db.query(HashedBreach).filter_by(username=username).all()
    salted_breaches = db.query(SaltedBreach).filter_by(username=username).all()
    return (plaintext_breaches, hashed_breaches, salted_breaches)
