from fastapi import FastAPI, HTTPException
from ldap3 import Server, Connection, ALL, SAFE_SYNC, ALL_ATTRIBUTES
from pydantic import BaseModel
import json
import os

USER = os.environ.get('LDAP_USER', '')
PASSWORD = os.environ.get('LDAP_PASSWORD', '')
SERVER = os.environ.get('LDAP_SERVER', '')

dn = SERVER.split('.')
entrydn = ','.join(f'dc={i}' for i in dn)

app = FastAPI()
server = Server(SERVER, get_info=ALL)

class LoginRequest(BaseModel):
    username: str
    password: str


def authenticate_ldap(username: str, password: str) -> bool:
    try:
        conn = Connection(server, f"{username}@{SERVER}", password, auto_bind=True)
    except:
        return False
    conn.unbind()
    return True

def get_ldap_groups(username: str) -> list:
    conn = Connection(server, USER, PASSWORD, auto_bind=True)
    status = conn.search(entrydn, f'(sAMAccountName={username})', attributes=ALL_ATTRIBUTES)
    if not status:
        return [False, [], ""]
    res = conn.entries
    conn.unbind()
    if len(res) == 0 or 'studbak' in res[0].entry_dn:
        return [False, [], ""]
    if 'memberOf' in res[0]:
        ad_groups = res[0]['memberOf']
    else:
        ad_groups = []
    if 'department' in res[0]:
        group = res[0]['department']
    else:
        group = ""
    name = res[0]['cn']
    return [True, list(ad_groups), str(group), str(name)]

@app.post("/login")
async def login(model: LoginRequest):
    username, password = model.username, model.password
    if not authenticate_ldap(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    res = get_ldap_groups(username)
    if not res[0]:
        raise HTTPException(status_code=404, detail="Not found")
    return {"username": username, "fullname": res[3], "roles": res[1], "group": res[2]}
