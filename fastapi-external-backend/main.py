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


hashHandler = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def check_password(encripted_password, hashed_password):
    encMessage = Coms.decryptMessage(encripted_password)
    return hashHandler.verify(encMessage, hashed_password)

'''
input:
    username: pgp encrypted username
    password: pgp encrypted password

output:
    true if the user is giving us the correct information
    false otherwise.

description:
    authenticated the current user by suppluing the pgp credentials
'''
def authenticate(username, password):
    username = Coms.decryptMessage(username)
    user = DbControls.getUser(username)
    if user is None:
        return False
    return check_password(password, DbControls.getPassword(user))


# DbControls.addUser("ADMIN", hashHandler.hash("hello world"))
# DbControls.addUserUrl("ADMIN", "HELLO", "hello world")
# print(DbControls.getUser("ADMIN"))
# print(DbControls.getUserUrls("ADMIN", "hello world"))

# print(authenticate(Coms.encryptMessage("ADMIN"), Coms.encryptMessage("hello world")))

# app = FastAPI() 






# print(check_password(Coms.encryptMessage("hello world"), hashHandler.hash("hello world")))
