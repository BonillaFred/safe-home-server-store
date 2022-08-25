'''
MAKING HTTPS CERTS:
openssl req -newkey rsa:4096 -new -nodes -keyout fastapi_pass.pem -out fastapi_csr.pem < make the csr
openssl x509 -req -in fastapi_csr.pem -signkey fastapi_pass.pem -out fastapi_certi.crt -extfile serverSubjectName.ext < signs the crt

** -extfile serverSubjectName.ext
is a file that contains the following exactly:
subjectAltName = DNS:localhost

running uvicorn as https:
uvicorn main:app --reload --ssl-keyfile './certs/fastapi_pass.pem' --ssl-certfile './certs/fastapi_certi.crt'
'''

from datetime import datetime, timedelta
from random import randint, random
from typing import List, Text, Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Internal module needed to simiplfy end-point code. 
import SafeComs as Coms

# Interna module needed to similify database access
import DatabaseAccess as DbControls

import json

with open('./env/env.json') as envVars:
    env = json.loads(envVars.read())

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    password: str

class URLGET(BaseModel):
    password: str

class URLADD(BaseModel):
    url: str
    password: str

hashHandler = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def check_password(encripted_password, hashed_password):
    # encMessage = Coms.decryptMessage(encripted_password)
    return hashHandler.verify(encripted_password, hashed_password)

'''
input:
    username: pgp encrypted username
    password: pgp encrypted password

output:
    the current user

description:
    authenticated the current user by suppluing the pgp credentials
'''
def authenticate(username, password):
    # username = Coms.decryptMessage(username)
    user = DbControls.getUser(username)
    if user is None:
        return False
    
    if check_password(password, DbControls.getPassword(user)):
        return user
    return None 

# following from: https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/
def create_access_token(data: dict, expires_delta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, env["SECRET_KEY"], algorithm=env["ALGORITHM"])
    return encoded_jwt

# following from: https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, env["SECRET_KEY"], algorithms=env["ALGORITHM"])
        username: str = payload.get("sub")
        #print(username)
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = DbControls.getUserEncrypted(username)
    if user is None:
        raise credentials_exception
    return user

# following from: https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/


# DbControls.addUser("ADMIN", hashHandler.hash("ADMIN"))
# DbControls.addUserUrl("ADMIN", "hello world", "ADMIN")

# DbControls.addUser("cat", hashHandler.hash("cat"))
# DbControls.addUserUrl("cat", "this is a test", "cat")

# DbControls.addUser("FuzzyPants", hashHandler.hash("c"))
# DbControls.addUserUrl("FuzzyPants", "this is mr fuzzy pants", "a")

# print(check_password(Coms.encryptMessage("hello world"), hashHandler.hash("hello world")))

# print(authenticate(Coms.encryptMessage("ADMIN"), Coms.encryptMessage("hello world")))
# enc = Coms.encryptMessage("hello world")
# enc = str(Coms.decryptMessage(enc))
# print(DbControls.getUserUrls("ADMIN", enc))

app = FastAPI() 

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    username = Coms.encryptMessage(form_data.username)
    password = Coms.encryptMessage(form_data.password)

    user = authenticate(Coms.decryptMessage(username), Coms.decryptMessage(password))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=env["ACCESS_TOKEN_EXPIRE_MINUTES"])
    access_token = create_access_token(
        data={"sub": str(user.username)[2:]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/logon", response_model=Token)
async def login_for_access_token(form_data: User):
    username = Coms.encryptMessage(form_data.username)
    password = Coms.encryptMessage(form_data.password)

    user = authenticate(Coms.decryptMessage(username), Coms.decryptMessage(password))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=env["ACCESS_TOKEN_EXPIRE_MINUTES"])
    access_token = create_access_token(
        data={"sub": str(user.username)[2:]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users/me/resources")
async def read_users_me(data: URLGET, current_user: User = Depends(get_current_user)):
    user = DbControls.getUserEncrypted(str(current_user.username)[2:])

    #Remove the following when the front-end is done
    #password = Coms.encryptMessage(data.password)

    password = Coms.decryptMessage(data.password)

    lists = DbControls.getUserUrls(user.username, password)
    return {"urls": lists}

@app.post("/users/me/addresource")
async def read_users_me(data: URLADD, current_user: User = Depends(get_current_user)):
    user = DbControls.getUserEncrypted(str(current_user.username)[2:])
    #needs encryption here
    
    #Remove these when the front-end is done being implemented
    # password = Coms.encryptMessage(data.password)
    # url = Coms.encryptMessage(data.url)

    password = Coms.decryptMessage(password)
    url = Coms.decryptMessage(url)

    res = DbControls.addUserUrl(user.username, url, password)
    return {"added": res}

@app.get('/handshake')
async def getPublicKey():
    return Coms.getPublicKey()
