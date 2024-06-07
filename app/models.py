from pydantic import BaseModel

# class ChangePasswordRequest(BaseModel):
#     old_password: str
#     password: str

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
