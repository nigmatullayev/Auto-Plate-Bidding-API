from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_admin: bool

class AutoPlateCreate(BaseModel):
    plate_number: str
    description: str
    deadline: datetime

class AutoPlateResponse(BaseModel):
    id: int
    plate_number: str
    description: str
    deadline: datetime
    is_active: bool

class BidCreate(BaseModel):
    amount: float
    plate_id: int

class BidResponse(BaseModel):
    id: int
    amount: float
    user_id: int
    plate_id: int
    created_at: datetime