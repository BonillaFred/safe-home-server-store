from datetime import datetime, timedelta
from typing import Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Internal module needed to simiplfy end-point code.
import SafeComs as Coms

hashHandler = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# app = FastAPI()

# 1. add user db( sql )
#   1.1: User: User
#        -path: str contains a path to the users enc files.
#                   must never expose the top level location
#                   of each file.
#         -username: str
#         -passwordHash: str
#         -(?) public key *force them to use it.
#
# app = FastAPI()
# app = FastAPI()


def check_password(encripted_password, hashed_password):
    encMessage = Coms.decryptMessage(encripted_password)
    return hashHandler.verify(encMessage, hashed_password)



print(check_password(Coms.encryptMessage("hello world"), hashHandler.hash("hello world")))
