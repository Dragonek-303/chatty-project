#server.py
import secrets
import hashlib
import sqlite3
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import asyncio
import json

DB_PATH = "messenger.db"

# ---------- Baza danych ----------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Tryb WAL pozwala na jednoczesne odczyty podczas zapisu (unika blokad/opóźnień).
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
    """)
    # Migracja dla baz utworzonych przed dodaniem kolumny "deleted"
    try:
        conn.execute("ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # kolumna już istnieje
    conn.commit()
    conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

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

# ---------- Modele ----------
class RegisterRequest(BaseModel):
    email: str
    password: str

class AddFriendRequest(BaseModel):
    my_id: str
    friend_id: str

class BlockRequest(BaseModel):
    my_id: str
    target_id: str

class SendMessageRequest(BaseModel):
    sender_id: str
    receiver_id: str
    content: str

class DeleteMessageRequest(BaseModel):
    user_id: str
    message_id: int
    mode: str  # "me" albo "everyone"

# ---------- Przechowywanie połączeń WebSocket ----------
active_connections: dict[str, WebSocket] = {}

async def notify_user(user_id: str, message: dict):
    ws = active_connections.get(user_id)
    if ws:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            pass

# ---------- Endpointy REST ----------
@app.post("/register")
async def register(data: RegisterRequest):
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
                    conn.commit()
                    return {"user_id": uid}
                except sqlite3.IntegrityError:
                    pass
            raise HTTPException(500, "Could not generate unique ID")
        finally:
            conn.close()
    return await asyncio.to_thread(_register)

@app.post("/login")
async def login(data: RegisterRequest):
    def _login():
        conn = get_db()
        try:
            user = conn.execute("SELECT id, password_hash FROM users WHERE email = ?", (data.email,)).fetchone()
            if not user or not verify_password(data.password, user["password_hash"]):
                raise HTTPException(401, "Invalid credentials")
            return {"user_id": user["id"]}
        finally:
            conn.close()
    return await asyncio.to_thread(_login)

# ---------- Znajomi (z akceptacją zaproszeń) ----------
@app.post("/add_friend")
async def add_friend(data: AddFriendRequest):
    if data.my_id == data.friend_id:
        raise HTTPException(400, "Cannot add yourself")

    def _add():
        conn = get_db()
        try:
            if not conn.execute("SELECT id FROM users WHERE id = ?", (data.my_id,)).fetchone() \
               or not conn.execute("SELECT id FROM users WHERE id = ?", (data.friend_id,)).fetchone():
                raise HTTPException(404, "User not found")
            if conn.execute("SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?",
                            (data.my_id, data.friend_id)).fetchone():
                raise HTTPException(400, "Already friends")
            if conn.execute(
                "SELECT 1 FROM blocked_users WHERE (user_id=? AND blocked_id=?) OR (user_id=? AND blocked_id=?)",
                (data.my_id, data.friend_id, data.friend_id, data.my_id)).fetchone():
                raise HTTPException(403, "Blocked")

            # Jeśli druga strona już wysłała nam zaproszenie - od razu się przyjaźnimy (obie strony chciały).
            reverse = conn.execute("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
                                   (data.friend_id, data.my_id)).fetchone()
            if reverse:
                conn.execute("DELETE FROM friend_requests WHERE from_id=? AND to_id=?",
                             (data.friend_id, data.my_id))
                conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                             (data.my_id, data.friend_id))
                conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                             (data.friend_id, data.my_id))
                conn.commit()
                return {"status": "friend added", "auto_accepted": True}

            if conn.execute("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
                            (data.my_id, data.friend_id)).fetchone():
                raise HTTPException(400, "Request already sent")

            conn.execute("INSERT INTO friend_requests (from_id, to_id) VALUES (?, ?)",
                         (data.my_id, data.friend_id))
            conn.commit()
            return {"status": "request sent", "auto_accepted": False}
        finally:
            conn.close()

    result = await asyncio.to_thread(_add)
    if result.get("auto_accepted"):
        asyncio.create_task(notify_user(data.my_id, {"type": "friend_added", "data": {"friend_id": data.friend_id}}))
        asyncio.create_task(notify_user(data.friend_id, {"type": "friend_added", "data": {"friend_id": data.my_id}}))
    else:
        asyncio.create_task(notify_user(data.friend_id, {"type": "friend_request", "data": {"from_id": data.my_id}}))
    return result

@app.get("/friend_requests/{user_id}")
async def get_friend_requests(user_id: str):
    def _get():
        conn = get_db()
        try:
            rows = conn.execute("SELECT from_id FROM friend_requests WHERE to_id=?", (user_id,)).fetchall()
            return rows
        finally:
            conn.close()
    rows = await asyncio.to_thread(_get)
    return [r["from_id"] for r in rows]

@app.post("/accept_friend")
async def accept_friend(data: AddFriendRequest):
    # data.my_id = osoba akceptująca, data.friend_id = osoba, która zaprosiła
    def _accept():
        conn = get_db()
        try:
            if not conn.execute("SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
                                (data.friend_id, data.my_id)).fetchone():
                raise HTTPException(404, "No such request")
            conn.execute("DELETE FROM friend_requests WHERE from_id=? AND to_id=?",
                         (data.friend_id, data.my_id))
            conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                         (data.my_id, data.friend_id))
            conn.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)",
                         (data.friend_id, data.my_id))
            conn.commit()
            return {"status": "accepted"}
        finally:
            conn.close()
    result = await asyncio.to_thread(_accept)
    asyncio.create_task(notify_user(data.my_id, {"type": "friend_added", "data": {"friend_id": data.friend_id}}))
    asyncio.create_task(notify_user(data.friend_id, {"type": "friend_added", "data": {"friend_id": data.my_id}}))
    return result

@app.post("/decline_friend")
async def decline_friend(data: AddFriendRequest):
    # data.my_id = osoba odrzucająca, data.friend_id = osoba, która zaprosiła
    def _decline():
        conn = get_db()
        try:
            conn.execute("DELETE FROM friend_requests WHERE from_id=? AND to_id=?",
                         (data.friend_id, data.my_id))
            conn.commit()
            return {"status": "declined"}
        finally:
            conn.close()
    return await asyncio.to_thread(_decline)

@app.post("/remove_friend")
async def remove_friend(data: AddFriendRequest):
    def _remove():
        conn = get_db()
        try:
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (data.my_id, data.friend_id))
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (data.friend_id, data.my_id))
            conn.execute("DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
                         (data.my_id, data.friend_id, data.friend_id, data.my_id))
            conn.commit()
            return {"status": "friend removed"}
        finally:
            conn.close()
    result = await asyncio.to_thread(_remove)
    asyncio.create_task(notify_user(data.friend_id, {
        "type": "friend_removed", "data": {"friend_id": data.my_id}
    }))
    return result

@app.post("/block_user")
async def block_user(data: BlockRequest):
    def _block():
        conn = get_db()
        try:
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (data.my_id, data.target_id))
            conn.execute("DELETE FROM friendships WHERE user_id=? AND friend_id=?",
                         (data.target_id, data.my_id))
            conn.execute("DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
                         (data.my_id, data.target_id, data.target_id, data.my_id))
            conn.execute("INSERT OR IGNORE INTO blocked_users (user_id, blocked_id) VALUES (?, ?)",
                         (data.my_id, data.target_id))
            conn.commit()
            return {"status": "user blocked"}
        finally:
            conn.close()
    result = await asyncio.to_thread(_block)
    asyncio.create_task(notify_user(data.target_id, {
        "type": "friend_removed", "data": {"friend_id": data.my_id}
    }))
    return result

@app.post("/unblock_user")
async def unblock_user(data: BlockRequest):
    def _unblock():
        conn = get_db()
        try:
            conn.execute("DELETE FROM blocked_users WHERE user_id=? AND blocked_id=?",
                         (data.my_id, data.target_id))
            conn.commit()
            return {"status": "user unblocked"}
        finally:
            conn.close()
    return await asyncio.to_thread(_unblock)

@app.get("/blocked/{user_id}")
async def get_blocked(user_id: str):
    def _get():
        conn = get_db()
        try:
            rows = conn.execute("SELECT blocked_id FROM blocked_users WHERE user_id=?", (user_id,)).fetchall()
            return rows
        finally:
            conn.close()
    rows = await asyncio.to_thread(_get)
    return [r["blocked_id"] for r in rows]

@app.get("/friends/{user_id}")
async def get_friends(user_id: str):
    def _get():
        conn = get_db()
        try:
            rows = conn.execute("SELECT friend_id FROM friendships WHERE user_id=?", (user_id,)).fetchall()
            return rows
        finally:
            conn.close()
    rows = await asyncio.to_thread(_get)
    return [r["friend_id"] for r in rows]

# ---------- Wiadomości ----------
@app.post("/send")
async def send_message(data: SendMessageRequest):
    if not data.content.strip():
        raise HTTPException(400, "Empty message")

    def _send():
        conn = get_db()
        try:
            if not conn.execute("SELECT 1 FROM friendships WHERE user_id=? AND friend_id=?",
                               (data.sender_id, data.receiver_id)).fetchone():
                raise HTTPException(403, "Not friends")
            if conn.execute("SELECT 1 FROM blocked_users WHERE user_id=? AND blocked_id=?",
                            (data.receiver_id, data.sender_id)).fetchone():
                raise HTTPException(403, "Blocked")
            cursor = conn.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                                 (data.sender_id, data.receiver_id, data.content))
            msg_id = cursor.lastrowid
            conn.commit()
            msg = conn.execute("SELECT id, sender_id, receiver_id, content, timestamp FROM messages WHERE id=?",
                               (msg_id,)).fetchone()
            return msg
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

    asyncio.create_task(notify_user(data.receiver_id, {
        "type": "new_message",
        "data": payload
    }))

    return {"status": "message sent", "message": payload}

@app.post("/delete_message")
async def delete_message(data: DeleteMessageRequest):
    if data.mode not in ("me", "everyone"):
        raise HTTPException(400, "Invalid mode")

    def _delete():
        conn = get_db()
        try:
            msg = conn.execute("SELECT sender_id, receiver_id FROM messages WHERE id=?",
                               (data.message_id,)).fetchone()
            if not msg:
                raise HTTPException(404, "Message not found")
            if data.user_id not in (msg["sender_id"], msg["receiver_id"]):
                raise HTTPException(403, "Not your message")

            if data.mode == "everyone":
                if data.user_id != msg["sender_id"]:
                    raise HTTPException(403, "Only the sender can delete for everyone")
                conn.execute("UPDATE messages SET content='', deleted=1 WHERE id=?", (data.message_id,))
                other = msg["receiver_id"]
            else:
                conn.execute("INSERT OR IGNORE INTO message_hidden (user_id, message_id) VALUES (?, ?)",
                             (data.user_id, data.message_id))
                other = None
            conn.commit()
            return {"status": "deleted", "mode": data.mode, "other_user": other}
        finally:
            conn.close()

    result = await asyncio.to_thread(_delete)
    if result["mode"] == "everyone" and result["other_user"]:
        asyncio.create_task(notify_user(result["other_user"], {
            "type": "message_deleted", "data": {"message_id": data.message_id}
        }))
    return result

@app.get("/conversation/{user_id}/{friend_id}")
async def get_conversation(user_id: str, friend_id: str, offset: int = 0, limit: int = 50):
    def _get():
        conn = get_db()
        try:
            friendship = conn.execute(
                "SELECT 1 FROM friendships WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)",
                (user_id, friend_id, friend_id, user_id)).fetchone()
            if not friendship:
                raise HTTPException(403, "Not friends")
            rows = conn.execute(
                """SELECT m.id, m.sender_id, m.receiver_id, m.content, m.timestamp, m.deleted
                   FROM messages m
                   LEFT JOIN message_hidden h ON h.message_id = m.id AND h.user_id = ?
                   WHERE ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?))
                     AND h.message_id IS NULL
                   ORDER BY m.id ASC LIMIT ? OFFSET ?""",
                (user_id, user_id, friend_id, friend_id, user_id, limit, offset)).fetchall()
            return rows
        finally:
            conn.close()
    rows = await asyncio.to_thread(_get)
    return [{"id": r["id"], "from": r["sender_id"], "to": r["receiver_id"],
             "content": r["content"], "time": r["timestamp"], "deleted": bool(r["deleted"])} for r in rows]

# ---------- WebSocket ----------
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await websocket.accept()
    active_connections[user_id] = websocket
    try:
        while True:
            await websocket.receive_text()   # trzymaj połączenie
    except WebSocketDisconnect:
        pass
    finally:
        active_connections.pop(user_id, None)

@app.get("/ping")
async def ping():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, timeout_keep_alive=30)