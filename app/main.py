from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from ldap3 import Server, Connection, ALL,  ALL_ATTRIBUTES
from pydantic import BaseModel
import os
import jwt
from jwt.exceptions import InvalidTokenError

USER = os.environ.get('LDAP_USER', '')
PASSWORD = os.environ.get('LDAP_PASSWORD', '')
SERVER = os.environ.get('LDAP_SERVER', '')

dn = SERVER.split('.')
entrydn = ','.join(f'dc={i}' for i in dn)

SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30 # 30 days

app = FastAPI()
server = Server(SERVER, get_info=ALL)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# models
class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    fullname: str | None = None
    username: str | None = None
    group: str | None = None
    roles: list[str] = []


# functions
def authenticate_ldap(username: str, password: str) -> bool:
    """Auth user in ldap. If success return True, else False."""
    try:
        conn = Connection(server, f"{username}@{SERVER}", password, auto_bind=True)
    except:
        return False
    conn.unbind()
    return True

def get_ldap_user(username: str) -> User:
    """Get user info from ldap. If success return User else None."""
    conn = Connection(server, USER, PASSWORD, auto_bind=True)
    if not conn.search(entrydn, f'(sAMAccountName={username})', attributes=ALL_ATTRIBUTES):
        return [False, [], ""]
    res = conn.entries
    conn.unbind()
    if len(res) == 0 or 'studbak' in res[0].entry_dn:
        return [False, [], ""]
    user = User(username=username, fullname = str(res[0]['cn']))
    if 'memberOf' in res[0]:
        user.roles = res[0]['memberOf']
    if 'department' in res[0]:
        user.group = res[0]['department']
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create jwt token with data and expires_delta. If expires_delta is None, token will expire in 15 minutes."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """Get current user from jwt token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_ldap_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Check if user is active. If not, raise HTTPException."""
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """Get access token for user. If user not exist, raise HTTPException."""
    user_exist = authenticate_ldap(form_data.username, form_data.password)
    if not user_exist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@app.get("/me")
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Get current user."""
    return current_user
