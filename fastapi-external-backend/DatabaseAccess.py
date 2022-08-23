from operator import and_
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text, and_

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


userDBengine = create_engine("sqlite:///users.db", connect_args={"check_same_thread": False})
session = sessionmaker(bind=userDBengine)()
Base = declarative_base()

#SALT SHOULD BE MOVED TO ENV
with open('./env/salt.s', 'rb') as iv:
    SALT = iv.read()

with open('./env/dbKey.key', 'rb') as keyFile:
    crypto = Fernet(keyFile.read())

class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(Text, nullable=False)
    password = Column(Text, nullable=False)
    url = relationship("Url", cascade="all, delete-orphan")

    def __repr__(self):
        return str(self.id)

class Url(Base):
    __tablename__ = "url"
    id = Column(Integer, primary_key=True)
    url = Column(Text, nullable=False)
    parentId = Column(Integer, ForeignKey("user.id"))


    def __repr__(self) -> str:
        return str(self.id)

Base.metadata.create_all(userDBengine)

def getUser(username:str):
    #Really very bad design! Needs to be changed
    #Maybe I should be checking hashes instead. -\_(*.*)_/-
    users = session.query(User).all()
    for u in users:
        if crypto.decrypt(u.username).decode() == username:
            return u
    return None

def getUserEncrypted(username: str):
    username = crypto.decrypt(bytes(username, 'utf-8')).decode()
    users = session.query(User).all()
    for u in users:
        if crypto.decrypt(u.username).decode() == username:
            return u
    return None

def addUser(username: str, password: str):
    userHolder = None
    try:
        if(getUser(username) is None):
            username = crypto.encrypt(bytes(username, 'utf-8'))
            password = crypto.encrypt(bytes(password, 'utf-8'))
            userHolder = User(username=username, password=password)
            session.add(userHolder)
            session.commit()
        else:
            raise NameError("User already exsits, cannot be added")
    except Exception as e:
        # Find some log message to place here
        print("Error Found:" + str(e))
        return False
    return userHolder.id

def searchUrl(user, urlString:str, pbeCrypto: Fernet):
    for url in user.url:
        if pbeCrypto.decrypt(url.url).decode() == urlString:
            return url
    return None

def pbeFernet(password: bytes):
    password = bytes(password, 'utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512,
        length=32,
        salt=SALT,
        iterations= 580000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)

def addUserUrl(username:str, urlString: str, password: str):
    pbeCrypto = pbeFernet(password)
    try:
        user = getUser(username=crypto.decrypt(username).decode())
        if searchUrl(user, urlString, pbeCrypto) is None:
            url = Url(url=pbeCrypto.encrypt(bytes(urlString, 'utf-8')), parentId=user.id)    
            session.add(url)
            session.commit()
        else:
            raise NameError("URL already exsits for user. Cannot be re-added " + str(urlString))
    except Exception as e:
        # Find some better way to do logs
        print("Error Found: " + str(e))
        return False
    return True

def getUserUrls(username:str, password: str):
    try:
        pbeCrypto = pbeFernet(password)

        user = getUser(username=crypto.decrypt(username).decode())

        # need to decrypt url list sadly
        urlList = []
        for url in user.url:
            urlList.append(pbeCrypto.decrypt(url.url).decode())
        return urlList
    except Exception as e:
        # Find some better way to do logs
        print("Error Found: " + str(e))
        return False

def deleteUser(username:str):
    try:
        user = getUser(username)
        deleteUrls(user.url)
        session.delete(user)
        session.commit()
    except Exception as e:
        # Find some better way to do logs
        print(e)
        return False
    return True

def getPassword(user):
    try:
        return crypto.decrypt(user.password).decode()
    except Exception as e:
        print(e)
    return None
