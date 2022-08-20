from datetime import datetime, timedelta
from typing import Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

import requests

import json

def requestCheck(req: requests.request):
    if req is None:
        raise NameError("Null request: Call admin")
    if req.status_code != 200:
        raise NameError("Request failed with code: " + str(req.status_code))
    return req.json()


def makeRequest(url: str, data: dict = None):
    fetched = None
    try:
        if(data is None):
            fetched = requests.get(url, verify='./env/certs/serverCert.crt')
        else:
            fetched = requests.post(url, json=data, verify='./env/certs/serverCert.crt')
        fetched = requestCheck(fetched)
    except Exception as e:
        print("Failed to get data:\n" + str(e))
        exit(-1)

    return fetched


hashHandler = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


pubKey = makeRequest('https://localhost:8080/publickey')
print(pubKey)

# app = FastAPI() 

def check_password(encripted_password, hashed_password):
    encMessage = makeRequest('https://localhost:8080/decrypt', data={"message":encripted_password})
    return hashHandler.verify(encMessage, hashed_password)





pubKey["message"] = "aaaaaa"

encMessage = makeRequest('https://localhost:8080/encrypt', data=pubKey)

print(check_password(encMessage, hashHandler.hash("not today")))