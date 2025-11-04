import os
import secrets
import hashlib
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import Admin, Student, Booking, Settings, SlotOverride

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ Utils ------------------
WEEK_SLOTS = [
    ("10:20", "11:20"),
    ("11:25", "12:25"),
    ("12:30", "13:30"),
    ("15:00", "16:00"),
    ("16:05", "17:05"),
    ("17:10", "18:10"),
    ("18:15", "19:15"),
]

DISABLED_WEDNESDAY = {("12:30","13:30"), ("15:00","16:00")}

DEFAULT_ADMIN_EMAIL = "autoscuolamissori@gmail.com"
DEFAULT_ADMIN_PASSWORD = "Buck2025@"

def sha256_hash(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

# Authentication helpers (token stored in DB for simplicity)

def issue_session(collection_name: str, user_filter: Dict) -> str:
    token = secrets.token_hex(24)
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    db[collection_name].update_one(user_filter, {"$push": {"sessions": {"token": token, "expires_at": expires}}})
    return token

async def get_settings() -> dict:
    try:
        doc = db["settings"].find_one({})
        if not doc:
            # initialize defaults
            s = Settings()
            try:
                create_document("settings", s)
                doc = db["settings"].find_one({})
            except Exception:
                # Fallback to in-memory default read-only if write not allowed
                doc = s.model_dump()
        return doc
    except Exception:
        # If DB not reachable at all, return sane defaults
        return Settings().model_dump()

# --------------- Startup: ensure admin ---------------
@app.on_event("startup")
async def ensure_admin():
    try:
        existing = db["admin"].find_one({"email": DEFAULT_ADMIN_EMAIL})
        if not existing:
            salt = secrets.token_hex(8)
            pw_hash = sha256_hash(DEFAULT_ADMIN_PASSWORD, salt)
            admin = Admin(email=DEFAULT_ADMIN_EMAIL, password_hash=pw_hash, salt=salt, sessions=[])
            try:
                create_document("admin", admin)
            except Exception:
                # ignore if quota or write restrictions prevent creating now
                pass
    except Exception:
        # ignore DB issues at startup so server can boot
        pass

# ----------------- Models ------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    token: str
    role: str

class StudentCreateRequest(BaseModel):
    name: str
    email: EmailStr

class SettingsUpdate(BaseModel):
    school_name: Optional[str] = None
    instructor_emails: Optional[List[EmailStr]] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: Optional[bool] = None
    guide_labels: Optional[Dict[str, str]] = None

class BookingRequest(BaseModel):
    date: str
    start: str
    end: str
    student_id: Optional[str] = None  # admin can book for a student
    notes: Optional[str] = None
    guide_type: Optional[str] = "standard"

# ----------------- Auth dependencies ------------------

def get_admin_from_token(x_token: Optional[str] = Header(None)):
    if not x_token:
        raise HTTPException(status_code=401, detail="Token mancante")
    now = datetime.now(timezone.utc)
    doc = db["admin"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}})
    if not doc:
        raise HTTPException(status_code=401, detail="Token non valido")
    return doc


def get_student_from_token(x_token: Optional[str] = Header(None)):
    if not x_token:
        raise HTTPException(status_code=401, detail="Token mancante")
    now = datetime.now(timezone.utc)
    doc = db["student"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}})
    if not doc:
        raise HTTPException(status_code=401, detail="Token non valido")
    return doc

# ----------------- Email ------------------

def send_email(to_email: str, subject: str, html_body: str):
    try:
        settings = db["settings"].find_one({}) or {}
    except Exception:
        settings = {}
    host = settings.get("smtp_host")
    user = settings.get("smtp_user")
    password = settings.get("smtp_password")
    port = int(settings.get("smtp_port", 587) or 587)
    use_tls = settings.get("smtp_use_tls", True)

    if not host or not user or not password:
        # If SMTP not configured, skip silently
        return False

    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_email

    try:
        with smtplib.SMTP(host, port) as server:
            if use_tls:
                server.starttls()
            server.login(user, password)
            server.sendmail(user, [to_email], msg.as_string())
        return True
    except Exception:
        return False

# --------------- Auth endpoints ----------------
@app.post("/auth/login_admin", response_model=LoginResponse)
def login_admin(payload: LoginRequest):
    admin = db["admin"].find_one({"email": payload.email})
    if not admin:
        # Bootstrap: if default admin credentials are used and admin doesn't exist, create it
        if payload.email == DEFAULT_ADMIN_EMAIL and payload.password == DEFAULT_ADMIN_PASSWORD:
            salt = secrets.token_hex(8)
            pw_hash = sha256_hash(DEFAULT_ADMIN_PASSWORD, salt)
            admin_doc = Admin(email=DEFAULT_ADMIN_EMAIL, password_hash=pw_hash, salt=salt, sessions=[])
            create_document("admin", admin_doc)
            admin = db["admin"].find_one({"email": payload.email})
        else:
            raise HTTPException(status_code=401, detail="Credenziali non valide")
    if admin["password_hash"] != sha256_hash(payload.password, admin["salt"]):
        raise HTTPException(status_code=401, detail="Credenziali non valide")
    token = issue_session("admin", {"email": payload.email})
    return {"token": token, "role": "admin"}

@app.post("/auth/login_student", response_model=LoginResponse)
def login_student(payload: LoginRequest):
    student = db["student"].find_one({"email": payload.email, "is_active": True})
    if not student:
        raise HTTPException(status_code=401, detail="Credenziali non valide")
    if student["password_hash"] != sha256_hash(payload.password, student["salt"]):
        raise HTTPException(status_code=401, detail="Credenziali non valide")
    token = issue_session("student", {"email": payload.email})
    return {"token": token, "role": "student"}

# --------------- Settings ----------------
@app.get("/settings")
async def read_settings():
    s = await get_settings()
    # Hide smtp password
    if "smtp_password" in s:
        s["smtp_password"] = "*****" if s["smtp_password"] else None
    return s

@app.put("/settings")
async def update_settings(payload: SettingsUpdate, admin=Depends(get_admin_from_token)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    db["settings"].update_one({}, {"$set": update}, upsert=True)
    return await get_settings()

# --------------- Students (admin) ---------------
@app.get("/students")
def list_students(admin=Depends(get_admin_from_token)):
    items = list(db["student"].find({}, {"password_hash": 0, "salt": 0, "sessions": 0}))
    for it in items:
        it["_id"] = str(it["_id"])
    return items

@app.post("/students")
def create_student(payload: StudentCreateRequest, admin=Depends(get_admin_from_token)):
    if db["student"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email già registrata")
    raw_password = secrets.token_urlsafe(8)
    salt = secrets.token_hex(8)
    pw_hash = sha256_hash(raw_password, salt)
    s = Student(name=payload.name, email=payload.email, password_hash=pw_hash, salt=salt)
    student_id = create_document("student", s)

    # email credentials
    html = f"""
    <p>Ciao {payload.name},</p>
    <p>Il tuo account per le guide di guida è stato creato.</p>
    <p>Credenziali:</p>
    <ul>
      <li>Email: {payload.email}</li>
      <li>Password: {raw_password}</li>
    </ul>
    <p>Ti consigliamo di cambiarla al primo accesso.</p>
    """
    send_email(payload.email, "Credenziali accesso Autoscuola", html)

    return {"id": student_id}

@app.delete("/students/{student_id}")
def delete_student(student_id: str, admin=Depends(get_admin_from_token)):
    from bson import ObjectId
    db["student"].delete_one({"_id": ObjectId(student_id)})
    # Also delete bookings by this student
    db["booking"].delete_many({"student_id": student_id})
    return {"status": "ok"}

# --------------- Slots & Calendar ---------------

def is_wednesday_disabled(date_str: str, start: str, end: str) -> bool:
    # Wednesday = 2 (Mon=0)
    dt = datetime.fromisoformat(date_str)
    if dt.weekday() == 2 and (start, end) in DISABLED_WEDNESDAY:
        return True
    return False

@app.get("/calendar")
def get_calendar(weekStart: str, x_token: Optional[str] = Header(None)):
    # weekStart is Monday date
    start_dt = datetime.fromisoformat(weekStart)
    days = [start_dt + timedelta(days=i) for i in range(5)]  # Mon-Fri

    # Load bookings for the week
    dates = [d.strftime('%Y-%m-%d') for d in days]
    bookings = list(db["booking"].find({"date": {"$in": dates}, "status": "active"}))
    # Determine visibility (admin sees names, student doesn't see names of others)
    is_admin = False
    student_id = None
    if x_token:
        now = datetime.now(timezone.utc)
        if db["admin"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}}):
            is_admin = True
        else:
            s = db["student"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}})
            if s:
                student_id = str(s["_id"]) if isinstance(s["_id"], type(bookings[0]["_id"]) if bookings else str) else None

    # Load overrides
    overrides = list(db["slotoverride"].find({"date": {"$in": dates}}))

    cal = {}
    for d in days:
        date_str = d.strftime('%Y-%m-%d')
        day_slots = []
        for (st, en) in WEEK_SLOTS:
            enabled = not is_wednesday_disabled(date_str, st, en)
            # apply overrides
            for ov in overrides:
                if ov.get("date") == date_str and ov.get("start") == st and ov.get("end") == en:
                    enabled = ov.get("enabled", True)
            book = next((b for b in bookings if b["date"] == date_str and b["start"] == st and b["end"] == en and b["status"] == "active"), None)
            status = "libero" if enabled and not book else ("occupato" if book else ("disabilitato"))
            info = None
            if book:
                info = {
                    "booking_id": str(book["_id"]),
                    "student_id": book.get("student_id"),
                    "guide_type": book.get("guide_type", "standard"),
                }
                if is_admin:
                    info["student_name"] = db["student"].find_one({"_id": __import__('bson').ObjectId(book["student_id"])})["name"] if book.get("student_id") else ""
                elif student_id and book.get("student_id") == student_id:
                    info["mine"] = True
            day_slots.append({
                "date": date_str,
                "start": st,
                "end": en,
                "enabled": enabled,
                "status": status,
                "info": info
            })
        cal[date_str] = day_slots
    return {"calendar": cal}

@app.post("/slots")
def set_slot_override(override: SlotOverride, admin=Depends(get_admin_from_token)):
    # upsert
    db["slotoverride"].update_one({"date": override.date, "start": override.start, "end": override.end}, {"$set": override.model_dump()}, upsert=True)
    return {"status": "ok"}

# --------------- Bookings ---------------

def count_bookings_same_day(student_id: str, date: str) -> int:
    return db["booking"].count_documents({"student_id": student_id, "date": date, "status": "active"})


def are_non_consecutive(existing: List[dict], new_start: str, new_end: str) -> bool:
    # Non-consecutive: new slot must not be immediately adjacent by schedule order
    order = [s for s, e in WEEK_SLOTS]
    idx_new = order.index(new_start)
    existing_indices = [order.index(b["start"]) for b in existing]
    return all(abs(idx_new - i) > 1 for i in existing_indices)

@app.post("/book")
def create_booking(req: BookingRequest, x_token: Optional[str] = Header(None)):
    # Determine actor
    now = datetime.now(timezone.utc)
    is_admin = False
    actor_student_id = None
    if x_token and db["admin"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}}):
        is_admin = True
    else:
        s = None
        if x_token:
            s = db["student"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}})
        if not s:
            raise HTTPException(status_code=401, detail="Non autorizzato")
        actor_student_id = str(s["_id"])

    date_str = req.date
    start, end = req.start, req.end

    # Check slot enabled
    if is_wednesday_disabled(date_str, start, end):
        # Only admin can modify Wednesday disabled
        if not is_admin:
            raise HTTPException(status_code=400, detail="Fascia oraria non disponibile il mercoledì")
    # Check override
    ov = db["slotoverride"].find_one({"date": date_str, "start": start, "end": end})
    if ov and not ov.get("enabled", True) and not is_admin:
        raise HTTPException(status_code=400, detail="Fascia oraria disabilitata")

    # Check already booked
    exists = db["booking"].find_one({"date": date_str, "start": start, "end": end, "status": "active"})
    if exists:
        raise HTTPException(status_code=400, detail="Fascia oraria già occupata")

    # Determine target student
    target_student_id = req.student_id if (is_admin and req.student_id) else actor_student_id
    if not target_student_id:
        raise HTTPException(status_code=400, detail="Studente non specificato")

    # Enforce per-day rules for student if not admin override
    if not is_admin:
        count_today = count_bookings_same_day(target_student_id, date_str)
        if count_today >= 2:
            raise HTTPException(status_code=400, detail="Massimo 2 lezioni al giorno")
        if count_today >= 1:
            existing = list(db["booking"].find({"student_id": target_student_id, "date": date_str, "status": "active"}))
            if not are_non_consecutive(existing, start, end):
                raise HTTPException(status_code=400, detail="Lezioni non possono essere consecutive nello stesso giorno")

    # Validate and set guide type
    guide_type = (req.guide_type or "standard").upper() if req.guide_type in ["A","B","C"] else (req.guide_type or "standard")
    if guide_type not in ["standard", "A", "B", "C"]:
        guide_type = "standard"

    b = Booking(date=date_str, start=start, end=end, student_id=target_student_id, status="active", created_by="admin" if is_admin else "student", created_at=datetime.now(timezone.utc), notes=req.notes, guide_type=guide_type)
    bid = create_document("booking", b)

    return {"id": bid}

@app.get("/bookings")
def list_bookings(admin=Depends(get_admin_from_token)):
    items = list(db["booking"].find({}, sort=[("date", 1), ("start", 1)]))
    for it in items:
        it["_id"] = str(it["_id"])
    return items

@app.delete("/bookings/{booking_id}")
def cancel_booking(booking_id: str, x_token: Optional[str] = Header(None)):
    from bson import ObjectId
    now = datetime.now(timezone.utc)
    is_admin = False
    sdoc = None
    if x_token and db["admin"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}}):
        is_admin = True
    else:
        if x_token:
            sdoc = db["student"].find_one({"sessions.token": x_token, "sessions.expires_at": {"$gt": now}})
        if not sdoc:
            raise HTTPException(status_code=401, detail="Non autorizzato")

    b = db["booking"].find_one({"_id": ObjectId(booking_id)})
    if not b:
        raise HTTPException(status_code=404, detail="Prenotazione non trovata")

    if not is_admin:
        if b.get("student_id") != str(sdoc["_id"]):
            raise HTTPException(status_code=403, detail="Non puoi cancellare prenotazioni di altri")
        # 24h rule
        lesson_dt = datetime.fromisoformat(b["date"] + "T" + b["start"] + ":00")
        if lesson_dt - datetime.now() < timedelta(hours=24):
            raise HTTPException(status_code=400, detail="Cancellazioni sotto 24 ore solo dall'amministratore")

    db["booking"].update_one({"_id": ObjectId(booking_id)}, {"$set": {"status": "cancelled"}})
    return {"status": "ok"}

# ----------------- Misc ------------------
@app.get("/")
def read_root():
    return {"message": "Backend attivo"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available" if db is None else "✅ Connected",
    }
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
