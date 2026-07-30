#server.py
import logging
import os
import re
import secrets
import hashlib
import asyncio
import json
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI, HTTPException, WebSocket, WebSocketDisconnect,
    Request, Header, Depends
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, field_validator
# import pysqlite3
# sys.modules['sqlite3'] = pysqlite3
import sqlite3

DB_PATH = "messenger.db"

# ---------- Stałe bezpieczeństwa / limity ----------
SESSION_TTL_DAYS = 30
MAX_MESSAGE_LENGTH = 4000
MIN_PASSWORD_LENGTH = 5
MAX_CONVERSATION_LIMIT = 200
RATE_LIMIT_WINDOW_SECONDS = 300     # 5 minut
RATE_LIMIT_MAX_ATTEMPTS = 10        # prób logowania/rejestracji w oknie
ID_RE = re.compile(r"^[0-9a-f]{32}$")   # format ID generowanego przez generate_user_id()

# --- KONFIGURACJA LOGOWANIA DLA FAIL2BAN ---
logger = logging.getLogger("fail2ban_logger")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("fastapi_security.log")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - IP: %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


def get_client_ip(request: Request) -> str:
    """
    WAŻNE: serwer działa BEZ reverse proxy przed sobą, więc nagłówek
    X-Forwarded-For jest dowolnie podrabialny przez klienta i NIE WOLNO
    mu ufać (dawało to możliwość fałszowania adresu przy banowaniu
    i obchodzenia rate-limitu). Bierzemy adres bezpośrednio z socketu TCP.
    """
    return request.client.host if request.client else "unknown"


# --- MIDDLEWARE WYŁAPUJĄCE BOTY (skanowanie 404) ---
class Fail2BanMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        ip = get_client_ip(request)
        if response.status_code == 404:
            logger.warning(f"BOT_SCAN_404 - IP:{ip} tried to access: {request.url.path}")
        return response


# ---------- Prosty rate limiter w pamięci (małe/średnie obciążenie -> wystarczy) ----------
_rate_buckets: dict[str, deque] = defaultdict(deque)


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX_ATTEMPTS:
        return False
    bucket.append(now)
    return True


# ---------- Baza danych ----------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 3000")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS friendships (
            user_id TEXT NOT NULL,
            friend_id TEXT NOT NULL,
            PRIMARY KEY (user_id, friend_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (friend_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS friend_requests (
            from_id TEXT NOT NULL,
            to_id TEXT NOT NULL,
            PRIMARY KEY (from_id, to_id),
            FOREIGN KEY (from_id) REFERENCES users(id),
            FOREIGN KEY (to_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS blocked_users (
            user_id TEXT NOT NULL,
            blocked_id TEXT NOT NULL,
            PRIMARY KEY (user_id, blocked_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (blocked_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            delivered INTEGER DEFAULT 0,
            deleted INTEGER DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS message_hidden (
            user_id TEXT NOT NULL,
            message_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, message_id),
            FOREIGN KEY (message_id) REFERENCES messages(id)
        );

        -- Indeksy pod najczęstsze zapytania (konwersacje rosną najszybciej)
        CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver
            ON messages (sender_id, receiver_id);
        CREATE INDEX IF NOT EXISTS idx_messages_receiver_sender
            ON messages (receiver_id, sender_id);
        CREATE INDEX IF NOT EXISTS idx_friend_requests_to
            ON friend_requests (to_id);
        CREATE INDEX IF NOT EXISTS idx_blocked_user
            ON blocked_users (user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_user
            ON sessions (user_id);
    """)
    # Migracja dla baz utworzonych przed dodaniem kolumny "deleted"
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(Fail2BanMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Domyślnie FastAPI zwraca przy błędach walidacji surową listę słowników
    (loc/msg/type/ctx) - dokładnie to widać na zrzucie ekranu z komunikatora.
    Zamieniamy to na zwykłe {"detail": "czytelny tekst"}, tak samo jak przy
    innych błędach (400/403/...), żeby klient mógł to wyświetlić bez zmian.
    """
    errors = exc.errors()
    if errors:
        msg = errors[0].get("msg", "Nieprawidłowe dane")
        # Pydantic v2 dokleja prefiks "Value error, " do komunikatów z naszych
        # własnych walidatorów (field_validator) - odcinamy go dla czytelności.
        prefix = "Value error, "
        if msg.startswith(prefix):
            msg = msg[len(prefix):]
    else:
        msg = "Nieprawidłowe dane"
    return JSONResponse(status_code=422, content={"detail": msg})


# ---------- Hasła ----------
PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return secrets.compare_digest(candidate.hex(), hash_hex)


def generate_user_id() -> str:
    return secrets.token_hex(16)


def _session_expired(expires_at_str: str) -> bool:
    """Odporne na sesje zapisane starą wersją kodu (naiwny datetime bez strefy)."""
    dt = datetime.fromisoformat(expires_at_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < datetime.now(timezone.utc)


def create_session(conn, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                 (token, user_id, expires))
    return token


def _simple_email_ok(email: str) -> bool:
    # Lekka walidacja bez dodatkowej zależności (email-validator).
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)) and len(email) <= 254


# ---------- Modele ----------
class AuthRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        v = v.strip().lower()
        if not _simple_email_ok(v):
            raise ValueError("Nieprawidłowy adres e-mail")
        return v

    @field_validator("password")
    @classmethod
    def password_len(cls, v):
        if len(v) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Hasło musi mieć co najmniej {MIN_PASSWORD_LENGTH} znaków")
        if len(v) > 256:
            raise ValueError("Hasło jest za długie")
        return v


class FriendIdRequest(BaseModel):
    friend_id: str


class TargetIdRequest(BaseModel):
    target_id: str


class SendMessageRequest(BaseModel):
    receiver_id: str
    content: str

    @field_validator("content")
    @classmethod
    def content_len(cls, v):
        if not v.strip():
            raise ValueError("Empty message")
        if len(v) > MAX_MESSAGE_LENGTH:
            raise ValueError(f"Message too long (max {MAX_MESSAGE_LENGTH} chars)")
        return v


class DeleteMessageRequest(BaseModel):
    message_id: int
    mode: str  # "me" albo "everyone"


def _require_valid_id(value: str):
    if not ID_RE.fullmatch(value):
        raise HTTPException(404, "User not found")


# ---------- Autoryzacja przez token sesyjny ----------
async def get_current_user(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization[len("Bearer "):].strip()

    def _check():
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)
            ).fetchone()
            if not row:
                raise HTTPException(401, "Invalid session")
            if _session_expired(row["expires_at"]):
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                raise HTTPException(401, "Session expired")
            return row["user_id"]
        finally:
            conn.close()

    return await asyncio.to_thread(_check)


async def _validate_ws_token(token: str) -> str | None:
    def _check():
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)
            ).fetchone()
            if not row:
                return None
            if _session_expired(row["expires_at"]):
                return None
            return row["user_id"]
        finally:
            conn.close()
    return await asyncio.to_thread(_check)


# ---------- Przechowywanie połączeń WebSocket ----------
active_connections: dict[str, WebSocket] = {}
_background_tasks: set[asyncio.Task] = set()


async def notify_user(user_id: str, message: dict):
    ws = active_connections.get(user_id)
    if ws:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            pass


def fire_and_forget(coro):
    """create_task, ale trzyma referencję, żeby zadanie nie zniknęło przed ukończeniem
    i żeby wyjątki nie ginęły bez śladu."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)

    def _done(t):
        _background_tasks.discard(t)
        exc = t.exception() if not t.cancelled() else None
        if exc:
            logger.warning(f"BACKGROUND_TASK_ERROR - {exc}")

    task.add_done_callback(_done)


# ---------- Endpointy REST: rejestracja / logowanie ----------
@app.post("/register")
async def register(data: AuthRequest, request: Request):
    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        logger.warning(f"RATE_LIMIT_REGISTER - IP:{ip}")
        raise HTTPException(429, "Too many attempts, try again later")

    def _register():
        conn = get_db()
        try:
            if conn.execute("SELECT id FROM users WHERE email = ?", (data.email,)).fetchone():
                raise HTTPException(400, "Email already registered")
            for _ in range(5):
                uid = generate_user_id()
                try:
                    conn.execute("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
                                 (uid, data.email, hash_password(data.password)))
                    token = create_session(conn, uid)
                    conn.commit()
                    return {"user_id": uid, "token": token}
                except sqlite3.IntegrityError:
                    pass
            raise HTTPException(500, "Could not generate unique ID")
        finally:
            conn.close()

    return await asyncio.to_thread(_register)


@app.post("/login")
async def login(data: AuthRequest, request: Request):
    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        logger.warning(f"RATE_LIMIT_LOGIN - IP:{ip}")
        raise HTTPException(429, "Too many attempts, try again later")

    def _login():
        conn = get_db()
        try:
            user = conn.execute("SELECT id, password_hash FROM users WHERE email = ?",
                                 (data.email,)).fetchone()
            if not user or not verify_password(data.password, user["password_hash"]):
                return None
            token = create_session(conn, user["id"])
            conn.commit()
            return {"user_id": user["id"], "token": token}
        finally:
            conn.close()

    result = await asyncio.to_thread(_login)
    if result is None:
        logger.warning(f"LOGIN_FAILED - IP:{ip} email:{data.email}")
        raise HTTPException(401, "Invalid credentials")
    return result


@app.post("/logout")
async def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):].strip()

        def _logout():
            conn = get_db()
            try:
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_logout)
    return {"status": "logged out"}


# ---------- Znajomi ----------
@app.post("/add_friend")
async def add_friend(data: FriendIdRequest, my_id: str = Depends(get_current_user)):
    _require_valid_id(data.friend_id)
    if my_id == data.friend_id:
        raise HTTPException(400, "Cannot add yourself")

    def _add():
        conn = get_db()
        try:
            if not conn.execute("SELECT id FROM users WHERE id = ?", (data.friend_id,)).fetchone():
                raise HTTPException(404, "User not found")
            if conn.execute("SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?",
                             (my_id, data.friend_id)).fetchone():
                raise HTTPException(400, "Already friends")
            if conn.execute(
                "SELECT 1 FROM blocked_users WHERE (user_id=? AND blocked_id=?) OR (user_id=? AND blocked_id=?)",
                (my_id, data.friend_id, data.friend_id, my_id)).fetchone():
                raise HTTPException(403, "Blocked")

            reverse = conn.execute("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
                                    (data.friend_id, my_id)).fetchone()
            if reverse:
                conn.execute("DELETE FROM friend_requests WHERE from_id=? AND to_id=?",
                             (data.friend_id, my_id))
                conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                             (my_id, data.friend_id))
                conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                             (data.friend_id, my_id))
                conn.commit()
                return {"status": "friend added", "auto_accepted": True}

            if conn.execute("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
                             (my_id, data.friend_id)).fetchone():
                raise HTTPException(400, "Request already sent")

            conn.execute("INSERT INTO friend_requests (from_id, to_id) VALUES (?, ?)",
                         (my_id, data.friend_id))
            conn.commit()
            return {"status": "request sent", "auto_accepted": False}
        finally:
            conn.close()

    result = await asyncio.to_thread(_add)
    if result.get("auto_accepted"):
        fire_and_forget(notify_user(my_id, {"type": "friend_added", "data": {"friend_id": data.friend_id}}))
        fire_and_forget(notify_user(data.friend_id, {"type": "friend_added", "data": {"friend_id": my_id}}))
    else:
        fire_and_forget(notify_user(data.friend_id, {"type": "friend_request", "data": {"from_id": my_id}}))
    return result


@app.get("/friend_requests")
async def get_friend_requests(user_id: str = Depends(get_current_user)):
    def _get():
        conn = get_db()
        try:
            return conn.execute("SELECT from_id FROM friend_requests WHERE to_id=?", (user_id,)).fetchall()
        finally:
            conn.close()
    rows = await asyncio.to_thread(_get)
    return [r["from_id"] for r in rows]


@app.post("/accept_friend")
async def accept_friend(data: FriendIdRequest, my_id: str = Depends(get_current_user)):
    def _accept():
        conn = get_db()
        try:
            if not conn.execute("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
                                 (data.friend_id, my_id)).fetchone():
                raise HTTPException(404, "No such request")
            conn.execute("DELETE FROM friend_requests WHERE from_id=? AND to_id=?",
                         (data.friend_id, my_id))
            conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                         (my_id, data.friend_id))
            conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                         (data.friend_id, my_id))
            conn.commit()
            return {"status": "accepted"}
        finally:
            conn.close()
    result = await asyncio.to_thread(_accept)
    fire_and_forget(notify_user(my_id, {"type": "friend_added", "data": {"friend_id": data.friend_id}}))
    fire_and_forget(notify_user(data.friend_id, {"type": "friend_added", "data": {"friend_id": my_id}}))
    return result


@app.post("/decline_friend")
async def decline_friend(data: FriendIdRequest, my_id: str = Depends(get_current_user)):
    def _decline():
        conn = get_db()
        try:
            conn.execute("DELETE FROM friend_requests WHERE from_id=? AND to_id=?",
                         (data.friend_id, my_id))
            conn.commit()
            return {"status": "declined"}
        finally:
            conn.close()
    return await asyncio.to_thread(_decline)


@app.post("/remove_friend")
async def remove_friend(data: FriendIdRequest, my_id: str = Depends(get_current_user)):
    def _remove():
        conn = get_db()
        try:
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (my_id, data.friend_id))
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (data.friend_id, my_id))
            conn.execute("DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
                         (my_id, data.friend_id, data.friend_id, my_id))
            conn.commit()
            return {"status": "friend removed"}
        finally:
            conn.close()
    result = await asyncio.to_thread(_remove)
    fire_and_forget(notify_user(data.friend_id, {"type": "friend_removed", "data": {"friend_id": my_id}}))
    return result


@app.post("/block_user")
async def block_user(data: TargetIdRequest, my_id: str = Depends(get_current_user)):
    def _block():
        conn = get_db()
        try:
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (my_id, data.target_id))
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (data.target_id, my_id))
            conn.execute("DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
                         (my_id, data.target_id, data.target_id, my_id))
            conn.execute("INSERT OR IGNORE INTO blocked_users (user_id, blocked_id) VALUES (?, ?)",
                         (my_id, data.target_id))
            conn.commit()
            return {"status": "user blocked"}
        finally:
            conn.close()
    result = await asyncio.to_thread(_block)
    fire_and_forget(notify_user(data.target_id, {"type": "friend_removed", "data": {"friend_id": my_id}}))
    return result


@app.post("/unblock_user")
async def unblock_user(data: TargetIdRequest, my_id: str = Depends(get_current_user)):
    def _unblock():
        conn = get_db()
        try:
            conn.execute("DELETE FROM blocked_users WHERE user_id=? AND blocked_id=?",
                         (my_id, data.target_id))
            conn.commit()
            return {"status": "user unblocked"}
        finally:
            conn.close()
    return await asyncio.to_thread(_unblock)


@app.get("/blocked")
async def get_blocked(user_id: str = Depends(get_current_user)):
    def _get():
        conn = get_db()
        try:
            return conn.execute("SELECT blocked_id FROM blocked_users WHERE user_id=?", (user_id,)).fetchall()
        finally:
            conn.close()
    rows = await asyncio.to_thread(_get)
    return [r["blocked_id"] for r in rows]


@app.get("/friends")
async def get_friends(user_id: str = Depends(get_current_user)):
    def _get():
        conn = get_db()
        try:
            return conn.execute("SELECT friend_id FROM friendships WHERE user_id=?", (user_id,)).fetchall()
        finally:
            conn.close()
    rows = await asyncio.to_thread(_get)
    return [r["friend_id"] for r in rows]


# ---------- Wiadomości ----------
@app.post("/send")
async def send_message(data: SendMessageRequest, sender_id: str = Depends(get_current_user)):
    def _send():
        conn = get_db()
        try:
            if not conn.execute("SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?",
                                 (sender_id, data.receiver_id)).fetchone():
                raise HTTPException(403, "Not friends")
            if conn.execute("SELECT 1 FROM blocked_users WHERE user_id=? AND blocked_id=?",
                             (data.receiver_id, sender_id)).fetchone():
                raise HTTPException(403, "Blocked")
            cursor = conn.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                                  (sender_id, data.receiver_id, data.content))
            msg_id = cursor.lastrowid
            conn.commit()
            return conn.execute(
                "SELECT id, sender_id, receiver_id, content, timestamp FROM messages WHERE id=?",
                (msg_id,)).fetchone()
        finally:
            conn.close()

    msg = await asyncio.to_thread(_send)

    payload = {
        "id": msg["id"],
        "from": msg["sender_id"],
        "to": msg["receiver_id"],
        "content": msg["content"],
        "time": msg["timestamp"],
        "deleted": False
    }
    fire_and_forget(notify_user(data.receiver_id, {"type": "new_message", "data": payload}))
    return {"status": "message sent", "message": payload}


@app.post("/delete_message")
async def delete_message(data: DeleteMessageRequest, user_id: str = Depends(get_current_user)):
    if data.mode not in ("me", "everyone"):
        raise HTTPException(400, "Invalid mode")

    def _delete():
        conn = get_db()
        try:
            msg = conn.execute("SELECT sender_id, receiver_id FROM messages WHERE id=?",
                               (data.message_id,)).fetchone()
            if not msg:
                raise HTTPException(404, "Message not found")
            if user_id not in (msg["sender_id"], msg["receiver_id"]):
                raise HTTPException(403, "Not your message")

            if data.mode == "everyone":
                if user_id != msg["sender_id"]:
                    raise HTTPException(403, "Only the sender can delete for everyone")
                conn.execute("UPDATE messages SET content='', deleted=1 WHERE id=?", (data.message_id,))
                other = msg["receiver_id"]
            else:
                conn.execute("INSERT OR IGNORE INTO message_hidden (user_id, message_id) VALUES (?, ?)",
                             (user_id, data.message_id))
                other = None
            conn.commit()
            return {"status": "deleted", "mode": data.mode, "other_user": other}
        finally:
            conn.close()

    result = await asyncio.to_thread(_delete)
    if result["mode"] == "everyone" and result["other_user"]:
        fire_and_forget(notify_user(result["other_user"],
                                     {"type": "message_deleted", "data": {"message_id": data.message_id}}))
    return result


@app.get("/conversation/{friend_id}")
async def get_conversation(friend_id: str, offset: int = 0, limit: int = 50,
                            user_id: str = Depends(get_current_user)):
    # Klient może zażądać dowolnie dużej wartości - twardo ją ograniczamy.
    limit = max(1, min(limit, MAX_CONVERSATION_LIMIT))
    offset = max(0, offset)

    def _get():
        conn = get_db()
        try:
            friendship = conn.execute(
                "SELECT 1 FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)",
                (user_id, friend_id, friend_id, user_id)).fetchone()
            if not friendship:
                raise HTTPException(403, "Not friends")
            return conn.execute(
                """SELECT m.id, m.sender_id, m.receiver_id, m.content, m.timestamp, m.deleted
                   FROM messages m
                   LEFT JOIN message_hidden h ON h.message_id = m.id AND h.user_id = ?
                   WHERE ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?))
                     AND h.message_id IS NULL
                   ORDER BY m.id DESC LIMIT ? OFFSET ?""",
                (user_id, user_id, friend_id, friend_id, user_id, limit, offset)).fetchall()
        finally:
            conn.close()

    rows = await asyncio.to_thread(_get)
    rows = list(reversed(rows))  # z powrotem w kolejności chronologicznej
    return [{"id": r["id"], "from": r["sender_id"], "to": r["receiver_id"],
             "content": r["content"], "time": r["timestamp"], "deleted": bool(r["deleted"])} for r in rows]


# ---------- WebSocket ----------
# Token NIE jest przyjmowany w query stringu URL-a - uvicorn (i każdy proxy
# stojący z przodu) loguje pełne URL-e żądań, więc token wyciekałby jawnym
# tekstem do logów serwera. Zamiast tego: łączymy się bez tokenu, akceptujemy
# połączenie, a klient jako pierwszą wiadomość wysyła JSON z tokenem.
AUTH_TIMEOUT_SECONDS = 10

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=AUTH_TIMEOUT_SECONDS)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4401)
        return

    try:
        auth_msg = json.loads(raw)
        token = auth_msg["token"]
    except (json.JSONDecodeError, KeyError, TypeError):
        await websocket.close(code=4400)
        return

    user_id = await _validate_ws_token(token)
    if not user_id:
        await websocket.close(code=4401)
        return

    # Jeśli to samo konto łączy się z drugiego miejsca, poprzednie połączenie
    # po prostu zostaje nadpisane w słowniku (można rozbudować o multi-device).
    active_connections[user_id] = websocket
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if active_connections.get(user_id) is websocket:
            active_connections.pop(user_id, None)


@app.get("/ping")
async def ping():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    # ---------------------------------------------------------------
    # Serwer stoi BEZPOŚREDNIO w internecie (bez reverse proxy), więc
    # TLS musi być terminowany tutaj, w uvicornie - inaczej hasła i
    # treść wiadomości lecą po sieci jawnym tekstem.
    #
    # Z certbotem (na domenie noip) najprościej tak (jednorazowo, port 80
    # musi być chwilowo wolny):
    #   sudo certbot certonly --standalone -d twojadomena.ddns.net
    # Certy wylądują w:
    #   /etc/letsencrypt/live/twojadomena.ddns.net/fullchain.pem
    #   /etc/letsencrypt/live/twojadomena.ddns.net/privkey.pem
    # Certyfikat trzeba odnawiać co ~60-90 dni (certbot renew) i
    # zrestartować ten proces po odnowieniu.
    #
    # Uruchomienie z TLS:
    #   SSL_CERTFILE=/etc/letsencrypt/live/twojadomena.ddns.net/fullchain.pem \
    #   SSL_KEYFILE=/etc/letsencrypt/live/twojadomena.ddns.net/privkey.pem \
    #   python server.py
    # ---------------------------------------------------------------
    ssl_certfile = os.environ.get("SSL_CERTFILE")
    ssl_keyfile = os.environ.get("SSL_KEYFILE")

    if not ssl_certfile or not ssl_keyfile:
        print("UWAGA: SSL_CERTFILE / SSL_KEYFILE nie ustawione - serwer wystartuje "
              "po zwykłym HTTP. Hasła i wiadomości NIE będą szyfrowane w sieci. "
              "Do użytku produkcyjnego na publicznej domenie skonfiguruj TLS "
              "(patrz komentarz powyżej).", file=sys.stderr)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        timeout_keep_alive=30,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )
