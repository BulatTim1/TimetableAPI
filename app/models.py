from enum import Enum
from pydantic import BaseModel

# class ChangePasswordRequest(BaseModel):
#     old_password: str
#     password: str

class Token(BaseModel):
    access_token: str | bytes
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    fullname: str | None = None
    username: str | None = None
    group: str | None = None
    roles: list[str] = []

class Notification(BaseModel):
    message: str
    title: str
    topics: list[str] = []
    ids: list[str] = []

class TimetableEnum(str, Enum):
    groups = "groups"
    teachers = "teachers"

class DayOfWeekEnum(str, Enum):
    monday = "monday"
    tuesday = "tuesday"
    wednesday = "wednesday"
    thursday = "thursday"
    friday = "friday"
    saturday = "saturday"
    sunday = "sunday"
    holidays = "holidays"

