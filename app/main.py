from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import logging
from typing import Annotated
import os
import hashlib

import httpx
from zeep import AsyncClient
from zeep.cache import SqliteCache
from zeep.transports import AsyncTransport
from models import *
from config import *
from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from ldap3 import Server, Connection, ALL,  ALL_ATTRIBUTES
import jwt
from jwt.exceptions import InvalidTokenError
import firebase_admin
from firebase_admin import auth, firestore, messaging

dn = LDAP_SERVER.split('.')
entrydn = ','.join(f'dc={i}' for i in dn)

SECRET_KEY = os.environ.get('SECRET_KEY', hashlib.sha512(os.urandom(256)).hexdigest())
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30 # 30 days

app = FastAPI(servers=[{"url": "http://178.205.174.82:7088/"}])
server = Server(LDAP_SERVER, get_info=ALL)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
logger = logging.getLogger("uvicorn")

basic_auth = (WSDL_USER, WSDL_PASSWORD)
httpx_client = httpx.AsyncClient(auth=basic_auth)
wsdl_client = None

# on first load
@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    firebase_admin.initialize_app()
    try:
        wsdl_client = AsyncClient(WSDL_LINK,
            transport=AsyncTransport(client=httpx_client, cache=SqliteCache())
        )
        logger.debug("Connected to 1c")
    except httpx.TransportError:
        logger.error("Can't connect to 1c")
    yield
    logger.debug("Shutting down")

# auth functions
async def authenticate_ldap(username: str, password: str) -> bool:
    """Auth user in ldap. If success return True, else False."""
    try:
        conn = Connection(server, f"{username}@{LDAP_SERVER}", password, auto_bind=True)
    except:
        return False
    conn.unbind()
    return True

async def get_ldap_user(username: str) -> User:
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


async def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
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
    user = await get_ldap_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    fb_user = auth.get_user_by_email(f"{user.username}@{LDAP_SERVER}")
    if not fb_user:
        fb_user = auth.create_user(email=f"{user.username}@{LDAP_SERVER}")
    user.uid = fb_user.uid
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Check if user is active. If not, raise HTTPException."""
    if not current_user:
        raise HTTPException(status_code=401)
    return current_user

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """Get access token for user. If user not exist, raise HTTPException."""
    user_exist = await authenticate_ldap(form_data.username, form_data.password)
    if not user_exist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@app.post("/app-token")
async def login_for_access_token_firebase(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
 ) -> Token:
    """Check user in ldap. If user exist then get or add user to firebase auth 
    and create custom token or else raise HTTPException."""
    user_exist = await authenticate_ldap(form_data.username, form_data.password)
    if not user_exist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = auth.get_user_by_email(f"{form_data.username}@{LDAP_SERVER}")
    if not user:
        user = auth.create_user(email=f"{form_data.username}@{LDAP_SERVER}", 
                                password=form_data.password)
    auth.update_user(user.uid, email_verified=True, password=form_data.password)
    token = auth.create_custom_token(user.uid)
    return Token(access_token=token, token_type="bearer")

# messaging functions
@app.post("/send-notification")
async def send_notification(notification: Notification, 
                            current_user: Annotated[User, Depends(get_current_active_user)]
                            ) -> list[dict]:
    """Send notifications to firebase topics or devices."""
    response = messaging.send_each([
        messaging.Message(
            notification=messaging.Notification(title=notification.title, 
                                                body=notification.message),
            topic=topic
        ) for topic in notification.topics
    ] + [
        messaging.Message(
            notification=messaging.Notification(title=notification.title, 
                                                body=notification.message),
            token=token
        ) for token in notification.ids
    ])
    return [{'success_count': r.success_count,
             'failure_count': r.failure_count} 
             for r in response]

# user functions
def getRole(uid: str) -> str | None:
    db = firestore.client()
    user_ref = db.collection("users").document(uid)
    user_data = user_ref.get().to_dict()
    return user_data.get("role")

# @app.get("/users")
# async def get_all_users(search: str = None, 
#                         current_user: Annotated[User, Depends(get_current_active_user)]):
#     db = firestore.client()
#     users_ref = db.collection("users")
#     users_snapshot = users_ref.stream()
#     users_data = []
#     for doc in users_snapshot:
#         if search and (
#             search not in user_data["fullname"] and search not in user_data["role"]
#         ):
#             continue
#         user_data["uid"] = doc.id
#         if user_data["params"].get("groups"):
#             user_data["params"]["groups"] = [
#                 i.path for i in user_data["params"]["groups"]
#             ]
#             # [i.get().to_dict() for i in user_data["params"]["groups"]]
#         if "group" in user_data["params"].keys():
#             # user_data["params"]["group"] = user_data["params"]["group"].get().to_dict()
#             user_data["params"]["group"] = user_data["params"]["group"].path
#         users_data.append(user_data)
#     if users_data is None:
#         raise HTTPException(404)
#     return users_data


def getStudentsOfGroupDevices(group_uid: str):
    db = firestore.client()
    students = (
        db.collection("users")
        .where("params.group", "==", db.collection("groups").document(group_uid))
        .stream()
    )
    devices = []
    for student in students:
        devices += student.to_dict()["devices"]
    return devices


def getUserDevices(teacher_uid: str):
    db = firestore.client()
    teacher = db.collection("users").document(teacher_uid).get().to_dict()
    return teacher["devices"]


def getAllDevices():
    devices = []
    db = firestore.client()
    users = db.collection("users").stream()
    for user in users:
        devices += user.to_dict()["devices"]
    return devices

# @app.get("/users/{uid}")
# async def getUser(uid: str, request: Request):
#     validate(request)
#     user_ref = db.collection("users").document(uid)
#     user_data = user_ref.get().to_dict()
#     if user_data is None:
#         raise HTTPException(404)
#     if "groups" in user_data["params"].keys():
#         user_data["params"]["groups_path"] = [
#             i.id for i in user_data["params"]["groups"]
#         ]
#         user_data["params"]["groups"] = [
#             i.get().to_dict() for i in user_data["params"]["groups"]
#         ]
#     if "group" in user_data["params"].keys():
#         user_data["params"]["group_path"] = user_data["params"]["group"].id
#         user_data["params"]["group"] = user_data["params"]["group"].get().to_dict()
#     try:
#         user = auth.get_user(uid)
#     except:
#         user_data["email"] = ""
#     return user_data


# @app.post("/users/{uid}")
# async def updateUser(uid: str, request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     print(j)
#     user = await getUser(uid, request)
#     group_uid = user["params"].pop("group_path", None)
#     if group_uid is not None:
#         user["params"]["group"] = db.collection("groups").document(group_uid)
#     if "fullname" in j.keys() and j["fullname"] is not None:
#         user["fullname"] = j["fullname"]
#     if "role" in j.keys() and j["role"] is not None:
#         user["role"] = j["role"]
#     if "devices" in j.keys() and j["devices"] is not None:
#         user["devices"] = j["devices"]
#     if "params" in j.keys() and j["params"] is not None: 
#         if "groups_path" in j["params"].keys() and j["params"]["groups_path"] is not None:
#             user["params"]["groups"] = [
#                 db.collection("groups").document(i) for i in j["params"]["groups_path"]
#             ]
#         if "group_path" in j["params"].keys() and j["params"]["group_path"] is not None:
#             user["params"]["group"] = db.collection("groups").document(
#                 j["params"]["group_path"]
#             )
#     if "admin" in role:
#         print(user)
#         db.collection("users").document(uid).set(user)
#     else:
#         raise HTTPException(404)
#     return "Success"


# @app.delete("/users/{uid}")
# async def deleteUser(uid: str, request: Request):
#     role = getRole(validate(request))
#     if "admin" in role:
#         db.collection("users").document(uid).delete()
#     else:
#         raise HTTPException(404)
#     return "Success"


# @app.post("/users")
# async def signup(request: Request):
#     # Get the request body
#     req = await request.json()
#     # Check if the request body contains the necessary fields
#     if "email" not in req.keys() or req["email"] is None:
#         raise HTTPException(detail={"message": "Missing Email"}, status_code=400)
#     if "password" not in req.keys() or req["password"] is None:
#         raise HTTPException(detail={"message": "Missing password"}, status_code=400)
#     if len(req["password"]) < 6:
#         raise HTTPException(detail={"message": "Password must be more than 6 characters"},status_code=400)
#     if "role" not in req.keys() or req["role"] is None:
#         raise HTTPException(detail={"message": "Missing role"}, status_code=400)
#     if "fullname" not in req.keys() or req["fullname"] is None:
#         raise HTTPException(detail={"message": "Missing fullname"}, status_code=400)
#     # Create a dictionary with the user's role and full name
#     data = {
#         "role": req["role"],
#         "fullname": req["fullname"],
#         "params": {},
#         "devices": [],
#     }
#     # Add the user to a group if they are in one
#     if "group_path" in req.keys():
#         data["params"]["group"] = db.collection("groups").document(req["group_path"])
#     # Add the user to multiple groups if they are in any
#     if "groups_path" in req.keys():
#         data["params"]["groups"] = [
#             db.collection("groups").document(i) for i in req["groups_path"]
#         ]
#     try:
#         # Create the user
#         user = auth.create_user(email=req["email"], password=req["password"])
#         # Add the user to the database
#         db.collection("users").document(user.uid).set(data)
#         # Send a response
#         return JSONResponse(
#             content={"message": f"Successfully created user {user.uid}"},
#             status_code=200,
#         )
#     except Exception as e:
#         # Delete the user if there are any errors
#         auth.delete_user(user.uid)
#         raise HTTPException(
#             detail={"message": f"Error creating user {user.uid}", "error": str(e)},
#             status_code=400,
#         )


# @app.get("/groups")
# async def get_all_groups(request: Request):
#     validate(request)
#     search = request.query_params.get("search")
#     ref = db.collection("groups")
#     snap = ref.stream()
#     groups = []
#     for doc in snap:
#         data = doc.to_dict()
#         if search and search not in data["group"]:
#             continue
#         data["uid"] = doc.id
#         groups.append(data)
#     if groups is None:
#         raise HTTPException(404)
#     return groups


# @app.get("/groups/{uid}")
# async def get_all_groups(uid: str, request: Request):
#     validate(request)
#     ref = db.collection("groups").document(uid)
#     data = ref.get().to_dict()
#     data["uid"] = uid
#     if data is None:
#         raise HTTPException(404)
#     return data


# @app.post("/groups")
# async def addGroup(request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     if "group" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing group name"}, status_code=400
#         )
#     if "enrollmentYear" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing enrollment year"}, status_code=400
#         )
#     if "issueYear" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing issue year"}, status_code=400
#         )
#     try:
#         data = {
#             "group": j["group"],
#             "enrollmentYear": int(j["enrollmentYear"]),
#             "issueYear": int(j["issueYear"]),
#         }
#     except Exception as e:
#         raise HTTPException(
#             detail={"message": "Error! Invalid data", "error": str(e)},
#             status_code=400,
#         )
#     if "admin" in role:
#         _, ref = db.collection("groups").add(data)
#     else:
#         raise HTTPException(404)
#     return {"uid": ref.id}


# @app.post("/groups/{uid}")
# async def updateGroup(uid: str, request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     if "group" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing group name"}, status_code=400
#         )
#     if "enrollmentYear" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing enrollment year"}, status_code=400
#         )
#     if "issueYear" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing issue year"}, status_code=400
#         )
#     data = {
#         "group": j["group"],
#         "enrollmentYear": j["enrollmentYear"],
#         "issueYear": j["issueYear"],
#     }
#     if "admin" in role:
#         db.collection("groups").document(uid).set(data)
#     else:
#         raise HTTPException(404)
#     return "Success"


# @app.delete("/groups/{uid}")
# async def deleteGroup(uid: str, request: Request):
#     role = getRole(validate(request))
#     if "admin" in role:
#         db.collection("groups").document(uid).delete()
#     else:
#         raise HTTPException(404)
#     return "Success"


# @app.get("/subjects")
# async def get_all_subjects(request: Request):
#     validate(request)
#     search = request.query_params.get("search")
#     ref = db.collection("subjects")
#     snap = ref.stream()
#     subjects = []
#     for doc in snap:
#         data = doc.to_dict()
#         if search and search not in data["name"]:
#             continue
#         data["uid"] = doc.id
#         subjects.append(data)
#     if subjects is None:
#         raise HTTPException(404)
#     return subjects


# @app.get("/subjects/{uid}")
# async def get_all_subjects(uid: str, request: Request):
#     validate(request)
#     ref = db.collection("subjects").document(uid)
#     data = ref.get().to_dict()
#     data["uid"] = uid
#     if data is None:
#         raise HTTPException(404)
#     return data


# @app.post("/subjects")
# async def addSubjects(request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     if "name" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing subject name"}, status_code=400
#         )
#     data = {
#         "name": j["name"],
#     }
#     if "admin" in role:
#         _, ref = db.collection("subjects").add(data)
#     else:
#         raise HTTPException(404)
#     return {"uid": ref.id}


# @app.post("/subjects/{uid}")
# async def updateSubjects(uid: str, request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     if "name" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing subject name"}, status_code=400
#         )
#     data = {
#         "name": j["name"],
#     }
#     if "admin" in role:
#         db.collection("subjects").document(uid).set(data)
#     else:
#         raise HTTPException(404)
#     return "Success"


# @app.delete("/subjects/{uid}")
# async def deleteSubjects(uid: str, request: Request):
#     role = getRole(validate(request))
#     if "admin" in role:
#         db.collection("subjects").document(uid).delete()
#     else:
#         raise HTTPException(404)
#     return "Success"

# @app.get("/holidays")
# async def getAllHolidays(request: Request):
#     validate(request)
#     ref = db.collection("holidays")
#     snap = ref.stream()
#     holidays = []
#     for doc in snap:
#         data = doc.to_dict()
#         data["year"] = doc.id
#         holidays.append(data)
#     if holidays is None:
#         raise HTTPException(404)
#     return holidays


# @app.get("/holidays/{year}")
# async def getAllHolidays(year: str, request: Request):
#     validate(request)
#     ref = db.collection("holidays").document(year)
#     data = ref.get().to_dict()
#     data["year"] = year
#     if data is None:
#         raise HTTPException(404)
#     return data


# @app.post("/holidays/{year}")
# async def addSubjects(year: str, request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     if "holidays" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing holidays"}, status_code=400
#         )
#     if "days" not in j["holidays"]:
#         raise HTTPException(
#             detail={"message": "Error! Missing holidays days"}, status_code=400
#         )
#     if "shortDays" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing shortDays"}, status_code=400
#         )
#     if "days" not in j["shortDays"]:
#         raise HTTPException(
#             detail={"message": "Error! Missing shortDays days"}, status_code=400
#         )
    
#     if "admin" in role:
#         existingDays = db.collection("holidays").document(year).get().to_dict()
#         if (existingDays is None):
#             existingDays = {"holiday": [], "shortDays": []}
#         for day in j["holidays"]["days"]:
#             existingDays["holidays"].append(day)
#         for day in j["shortDays"]["days"]:
#             existingDays["shortDays"].append(day)
#         db.collection("holidays").document(year).set(existingDays)
#     else:
#         raise HTTPException(404)
#     return {}


# @app.delete("/holidays/{year}")
# async def deleteSubjects(year: str, request: Request):
#     role = getRole(validate(request))
#     # if "admin" in role:
#         # db.collection("subjects").document(year).delete()
#     # else:
#     raise HTTPException(404)
#     return "Success"


# # @app.get("/temp/{type}")
# # async def getTempTimetables(type: TimetableEnum, request: Request):
# #     validate(request)
# #     ref = db.collection("temp").document(type.value)
# #     data = ref.get().to_dict()
# #     if data is None:
# #         raise HTTPException(404)
# #     return data

# @app.get("/timestamps")
# async def getAllSTimestamps(request: Request):
#     validate(request)
#     ref = db.collection("timestamps")
#     snap = ref.stream()
#     timestamps = []
#     for doc in snap:
#         data = doc.to_dict()
#         data["uid"] = doc.id
#         timestamps.append(data)
#     if timestamps is None:
#         raise HTTPException(404)
#     return timestamps


# @app.get("/timestamps/{uid}")
# async def getTimestamp(uid: str, request: Request):
#     validate(request)
#     ref = db.collection("timestamps").document(uid)
#     data = ref.get().to_dict()
#     data["uid"] = uid
#     if data is None:
#         raise HTTPException(404)
#     return data


# # TODO: более тщательная проверка
# @app.post("/timestamps")
# async def addTimestamp(request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     if len(j["days"]) == 0:
#         raise HTTPException(
#             detail={"message": "Error! Missing days for timestamps"}, status_code=400
#         )
#     if "times" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing timestamps"}, status_code=400
#         )
#     data = {
#         "days": j["days"],
#         "times": j["times"],
#     }
#     if "admin" in role:
#         _, ref = db.collection("timestamps").add(data)
#     else:
#         raise HTTPException(404)
#     return {"uid": ref.id}


# @app.post("/timestamps/{uid}")
# async def updateTimestamps(uid: str, request: Request):
#     role = getRole(validate(request))
#     j = await request.json()
#     if "name" not in j.keys():
#         raise HTTPException(
#             detail={"message": "Error! Missing subject name"}, status_code=400
#         )
#     data = {
#         "name": j["name"],
#     }
#     if "admin" in role:
#         db.collection("subjects").document(uid).set(data)
#     else:
#         raise HTTPException(404)
#     return "Success"


# @app.delete("/timestamps/{uid}")
# async def deleteTimestamps(uid: str, current_user: 
#                            Annotated[User, Depends(get_current_user)]):
#     role = getRole(auth.get_user(current_user.email).uid)
#     db = firestore.client()
#     if "admin" in role:
#         db.collection("timestamps").document(uid).delete()
#     else:
#         raise HTTPException(404)
#     return "Success"


# @app.get("/timetables/{type}")
# async def get_all_groups_timetables(type: TimetableEnum, 
#                                     current_user: Annotated[User, Depends(get_current_user)]):
#     isGroups = True
#     db = firestore.client()
#     if "groups" in type:
#         timetable_ref = db.collection("timetable_groups")
#     elif "teachers" in type:
#         isGroups = False
#         timetable_ref = db.collection("timetable_teachers")
#     else:
#         raise HTTPException(404)
#     snap = timetable_ref.stream()
#     timetables = []
#     for doc in snap:
#         data = doc.to_dict()
#         data["uid"] = doc.id
#         for i in data["dayOfWeek"].keys():
#             for j in data["dayOfWeek"][i].keys():
#                 data["dayOfWeek"][i][j]["subject_uid"] = data["dayOfWeek"][i][j][
#                     "subject"
#                 ].id
#                 data["dayOfWeek"][i][j]["subject"] = (
#                     data["dayOfWeek"][i][j]["subject"].get().to_dict()
#                 )
#                 if isGroups:
#                     data["dayOfWeek"][i][j]["teacher_uid"] = data["dayOfWeek"][i][j][
#                         "teacher"
#                     ]
#                     data["dayOfWeek"][i][j]["teacher"] = (
#                         data["dayOfWeek"][i][j]["teacher"].get().to_dict()
#                     )
#                 else:
#                     data["dayOfWeek"][i][j]["group_uid"] = data["dayOfWeek"][i][j][
#                         "group"
#                     ].id
#                     data["dayOfWeek"][i][j]["group"] = (
#                         data["dayOfWeek"][i][j]["group"].get().to_dict()
#                     )
#         timetables.append(data)
#     if len(timetables) == 0:
#         raise HTTPException(404)
#     return timetables


# @app.post("/timetables/{type}/{uid}")
# async def update_timetable(type: TimetableEnum, uid: str, 
#                            current_user: Annotated[User, Depends(get_current_user)]:
#     db = firestore.client()
#     isGroups = True
#     if "groups" in type:
#         timetable_ref = db.collection("timetable_groups").document(uid)
#     elif "teachers" in type:
#         isGroups = False
#         timetable_ref = db.collection("timetable_teachers").document(uid)
#     else:
#         raise HTTPException(404)

#     data = await request.json()
#     for i in data["dayOfWeek"].keys():
#         for j in data["dayOfWeek"][i].keys():
#             if isGroups:
#                 group_ref = db.collection("groups").document(
#                     data["dayOfWeek"][i][j]["group_uid"]
#                 )
#                 data["dayOfWeek"][i][j]["group"] = group_ref
#                 teacher_ref = db.collection("teachers").document(
#                     data["dayOfWeek"][i][j]["teacher_uid"]
#                 )
#                 data["dayOfWeek"][i][j]["teacher"] = teacher_ref
#             else:
#                 group_ref = db.collection("groups").document(
#                     data["dayOfWeek"][i][j]["group_uid"]
#                 )
#                 data["dayOfWeek"][i][j]["group"] = group_ref
#                 teacher_ref = db.collection("teachers").document(
#                     data["dayOfWeek"][i][j]["teacher_uid"]
#                 )
#                 data["dayOfWeek"][i][j]["teacher"] = teacher_ref
#             subject_ref = db.collection("subjects").document(
#                 data["dayOfWeek"][i][j]["subject_uid"]
#             )
#             data["dayOfWeek"][i][j]["subject"] = subject_ref

#     timetable_ref.set(data)
#     return {"uid": timetable_ref.id}


# def checkSubject(data: dict, isGroup: bool):
#     if "subject_uid" not in data.keys() or data["subject_uid"] is None:
#         raise HTTPException(detail={"message": "Missing subject"}, status_code=400)
#     db = firestore.client()
#     if db.collection("subjects").document(data["subject_uid"]).get().to_dict() is None:
#         raise HTTPException(detail={"message": "Wrong subject"}, status_code=400)
#     if "auditory" not in data.keys() or data["auditory"] is None:
#         raise HTTPException(detail={"message": "Missing auditory"}, status_code=400)
#     if isGroup and ("teacher_uid" not in data.keys() or data["teacher_uid"] is None):
#         raise HTTPException(detail={"message": "Missing teacher"}, status_code=400)
#     if (
#         isGroup
#         and db.collection("users").document(data["teacher_uid"]).get().to_dict() is None
#     ):
#         raise HTTPException(detail={"message": "Wrong teacher"}, status_code=400)
#     if not isGroup and ("group_uid" not in data.keys() or data["group_uid"] is None):
#         raise HTTPException(detail={"message": "Missing group"}, status_code=400)
#     if (
#         not isGroup
#         and db.collection("groups").document(data["group_uid"]).get().to_dict() is None
#     ):
#         raise HTTPException(detail={"message": "Wrong group"}, status_code=400)


@app.get("/me-ldap")
async def read_current_user_ldap(current_user: Annotated[User, Depends(get_current_active_user)]):
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

# async def get_groups():
#     """Get all groups from 1c soap."""
#     try:
#         res = await wsdl_client.service.GetGroup()
#         groups = [str(i) for i in res]
#         return groups
#     except:
#         return None

# async def get_teachers():
#     """Get all teachers from 1c soap."""
#     try:
#         res = await wsdl_client.service.GetTeacher()
#         teachers = [str(i) for i in res]
#         return teachers
#     except:
#         return None

# @app.get("/groups")
# async def get_groups_endpoint(current_user: Annotated[User, Depends(get_current_active_user)]):
#     """Get all groups."""
#     return await get_groups()

# @app.get("/teachers")
# async def get_teachers_endpoint(current_user: Annotated[User, Depends(get_current_active_user)]):
#     """Get all teachers."""
#     return await get_teachers()
