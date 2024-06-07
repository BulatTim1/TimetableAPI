from datetime import datetime, timedelta, timezone
from typing import Annotated
import os
import hashlib
from models import User, Token, TokenData
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from ldap3 import Server, Connection, ALL,  ALL_ATTRIBUTES
import jwt
from jwt.exceptions import InvalidTokenError
import httpx
from zeep import AsyncClient
from zeep.cache import SqliteCache
from zeep.transports import AsyncTransport

LDAP_USER = os.environ.get('LDAP_USER', '')
LDAP_PASSWORD = os.environ.get('LDAP_PASSWORD', '')
LDAP_SERVER = os.environ.get('LDAP_SERVER', '')

WSDL_USER = os.environ.get('WSDL_USER', '')
WSDL_PASSWORD = os.environ.get('WSDL_PASSWORD', '')
WSDL_LINK = os.environ.get('WSDL_LINK', '')

dn = LDAP_SERVER.split('.')
entrydn = ','.join(f'dc={i}' for i in dn)

SECRET_KEY = os.environ.get('SECRET_KEY', hashlib.sha512(os.urandom(256)).hexdigest())
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30 # 30 days

app = FastAPI()
server = Server(LDAP_SERVER, get_info=ALL)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

httpx_client = httpx.AsyncClient(auth=(WSDL_USER, WSDL_PASSWORD))
wsdl_client = AsyncClient(WSDL_LINK,
    transport=AsyncTransport(client=httpx_client, cache=SqliteCache())
)

# functions
def authenticate_ldap(username: str, password: str) -> bool:
    """Auth user in ldap. If success return True, else False."""
    try:
        conn = Connection(server, f"{username}@{LDAP_SERVER}", password, auto_bind=True)
    except:
        return False
    conn.unbind()
    return True

def get_ldap_user(username: str) -> User:
    """Get user info from ldap. If success return User else None."""
    conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True)
    if not conn.search(entrydn, f'(sAMAccountName={username})', attributes=ALL_ATTRIBUTES):
        return [False, [], ""]
    res = conn.entries
    conn.unbind()
    if len(res) == 0 or 'studbak' in res[0].entry_dn:
        return [False, [], ""]
    user = User(username=username, fullname = str(res[0]['cn']))
    if 'memberOf' in res[0]:
        user.roles = list(res[0]['memberOf'])
    if 'department' in res[0]:
        user.group = str(res[0]['department'])
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create jwt token with data and expires_delta. 
    If expires_delta is None, token will expire in 15 minutes."""
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

# TODO: fix DSID-03190EB2, problem 5003 (WILL_NOT_PERFORM) (maybe need base64 encode password?)
# @app.post("/change-password")
# async def change_password(
#     form_data: Annotated[ChangePasswordRequest, Depends()],
#     current_user: Annotated[User, Depends(get_current_active_user)],
# ) -> dict:
#     """Change user password. If user not exist, raise HTTPException."""
#     user_exist = authenticate_ldap(current_user.username, form_data.password)
#     if not user_exist:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     conn = Connection(server, f"{current_user.username}@{LDAP_SERVER}",
#                       form_data.password, auto_bind=True)
#     conn.extend.microsoft.modify_password(current_user.username,
#                                           form_data.password,
#                                           old_password=form_data.old_password)
#     conn.unbind()
#     return {"message": "Password changed successfully"}

async def get_groups():
    """Get all groups from 1c soap."""
    try:
        res = await wsdl_client.service.GetGroup()
        groups = [str(i) for i in res]
        return groups
    except:
        return None

async def get_teachers():
    """Get all teachers from 1c soap."""
    try:
        res = await wsdl_client.service.GetTeacher()
        teachers = [str(i) for i in res]
        return teachers
    except:
        return None


@app.get("/groups")
async def get_groups_endpoint(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Get all groups."""
    return await get_groups()

@app.get("/teachers")
async def get_teachers_endpoint(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Get all teachers."""
    return await get_teachers()
