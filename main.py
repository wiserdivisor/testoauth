import os
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from passlib.context import CryptContext
from jose import JWTError, jwt

# GLOBAL VARS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
SECRET_KEY = os.environ.get('SECRET_KEY')
JWT_ALGORITHM = os.environ.get('JWT_ALGO')
ACCESS_TOKEN_EXPIRE_MINS = int(os.environ.get('TOKEN_EXP_MINS'))

# DATABASE >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$codwF17jt4yE/csMfGCVTuRw6edNxTdl4/lPZ6C6KMFukFPfIvFLm",
        "isDisabled": False,
    },
    "alice": {
        "username": "alice",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$1DeA1EJsnj38sdkVob9AQuL6gg0rQWoYgsFlNxYUgeDJl2onExJEu",
        "isDisabled": True,
    },
}

# SCHEMAS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
class Token(BaseModel):
    access_token :str
    base_model :str

class TokenData(BaseModel):
    username :str

class User(BaseModel):
    username :str
    email :Optional[str] = None
    isDisabled :Optional[bool] = None

class UserInDB(User):
    hashed_password :str

# CALLABLES >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
pswrdContext = CryptContext(schemes=['bcrypt'], deprecated='auto')
bearer = OAuth2PasswordBearer(tokenUrl='token')
api = FastAPI()

# UTILITIES >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
def verify_password(plaintext, hashed):
    return pswrdContext.verify(plaintext, hashed)

def get_password_hash(password):
    return pswrdContext.hash(password)

def get_user(db, username:str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def auth_user(fake_users_db, username:str, password:str):
    user = get_user(fake_users_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data:dict, expires_delta:Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else :
        expire = datetime.now() + timedelta(minutes=5)
    to_encode.update({ 'exp':expire })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(token :str = Depends(bearer)):
    #ERROR
    credentials_exception =  HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Validation Error",
        headers={"WWW-Authenticate":"Bearer"}
    )

    #GET USERNAME FROM TOKEN
    try:
        print("TOKEN :: ",token)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        print("PAYLOAD : ",payload)
        username :str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    #IF DOSENT WORK
    except JWTError:
        raise credentials_exception

    #GET THE USER
    user = get_user(fake_users_db, username=token_data.username)

    #IF NO SUCH USER
    if user is None:
        raise credentials_exception

    #IF EVERYTHING IS COOL
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.isDisabled:
        raise HTTPException(status_code=400, details="Inactive User")
    return current_user


@api.post("/token")
async def auth_for_access_token(form_data : OAuth2PasswordRequestForm = Depends()):
    user = auth_user(fake_users_db, username=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate":"Bearer"},
        )
    token_expiry = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINS)
    access_token = create_access_token(
        data = { "sub":user.username }, expires_delta = token_expiry
    )

    return { "access_token":access_token, "token_type":"bearer" }


@api.get('/main/user')
async def current_user(current_user :User = Depends(get_current_user)):
    return current_user

@api.get('/main/user/items')
async def current_user_items(current_user :User = Depends(get_current_user)):
    return [{"item_id":"Foo","owner":current_user.username}]
