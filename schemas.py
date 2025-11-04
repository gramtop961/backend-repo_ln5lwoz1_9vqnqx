from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal, Dict
from datetime import datetime

# NOTE: Each class name is the collection name lowercased

class Admin(BaseModel):
    email: EmailStr
    password_hash: str
    salt: str
    sessions: Optional[List[dict]] = []  # {token, expires_at}

class Settings(BaseModel):
    school_name: str = Field(default="Autoscuola Missori")
    instructor_emails: List[EmailStr] = []
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    # Guide labels allow renaming A/B/C, defaults in Italian
    guide_labels: Dict[str, str] = Field(default_factory=lambda: {
        "A": "Notturna",
        "B": "Extraurbana",
        "C": "Autostrada",
    })

class Student(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    salt: str
    is_active: bool = True

class SlotOverride(BaseModel):
    # Admin can add/remove extra slots or disable/enable specific ones
    date: str  # YYYY-MM-DD
    start: str # HH:MM
    end: str   # HH:MM
    enabled: bool = True

class Booking(BaseModel):
    date: str  # YYYY-MM-DD
    start: str # HH:MM
    end: str   # HH:MM
    student_id: str
    status: Literal["active","cancelled"] = "active"
    created_by: Literal["student","admin"] = "student"
    created_at: Optional[datetime] = None
    notes: Optional[str] = None
    guide_type: Literal["standard", "A", "B", "C"] = "standard"
