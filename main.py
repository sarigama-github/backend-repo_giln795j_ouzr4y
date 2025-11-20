import os
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Cookie, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext
import socketio
from bson import ObjectId

from database import db

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "dev_super_secret_change_me")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))
FRONTEND_URL = os.getenv("FRONTEND_URL", "*")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def objid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MIN),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ----------------------------------------------------------------------------
# Pydantic Models
# ----------------------------------------------------------------------------
class RegisterBody(BaseModel):
    name: str
    username: str
    password: str


class LoginBody(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: str
    name: str
    username: str
    avatar: Optional[str] = None
    bio: Optional[str] = None
    last_seen: Optional[datetime] = None
    online: Optional[bool] = False


class ConversationCreate(BaseModel):
    participantId: Optional[str] = None
    isGroup: bool = False
    groupName: Optional[str] = None
    groupAvatar: Optional[str] = None
    participants: Optional[List[str]] = None


class MessageCreate(BaseModel):
    conversationId: str
    content: Optional[str] = None
    attachments: Optional[List[str]] = None


# ----------------------------------------------------------------------------
# FastAPI app and Socket.IO
# ----------------------------------------------------------------------------
fastapi_app = FastAPI()

fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL] if FRONTEND_URL != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
asgi_app = socketio.ASGIApp(sio, other_asgi_app=fastapi_app)

# Mapping of userId -> sid
connected_users: Dict[str, str] = {}


async def get_current_user_id(request: Request, token: Optional[str] = Cookie(default=None)) -> str:
    if token is None:
        # also allow Authorization: Bearer
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            token_val = auth.split(" ", 1)[1]
        else:
            raise HTTPException(status_code=401, detail="Not authenticated")
    else:
        token_val = token
    user_id = decode_token(token_val)
    return user_id


# ----------------------------------------------------------------------------
# Routes: Health & Test
# ----------------------------------------------------------------------------
@fastapi_app.get("/")
def read_root():
    return {"message": "Chat API running"}


@fastapi_app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {"backend": "ok", "database": "ok", "collections": collections}
    except Exception as e:
        return {"backend": "ok", "database": f"error: {str(e)}"}


# ----------------------------------------------------------------------------
# Routes: Auth
# ----------------------------------------------------------------------------
@fastapi_app.post("/auth/register")
def register(body: RegisterBody):
    users = db["users"]
    if users.find_one({"username": body.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    user_doc = {
        "name": body.name,
        "username": body.username,
        "password": hash_password(body.password),
        "avatar": None,
        "bio": "",
        "last_seen": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = users.insert_one(user_doc)
    return {"id": str(res.inserted_id)}


@fastapi_app.post("/auth/login")
def login(body: LoginBody, response: Response):
    users = db["users"]
    user = users.find_one({"username": body.username})
    if not user or not verify_password(body.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(str(user["_id"]))
    # HTTP-only cookie
    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=JWT_EXPIRES_MIN * 60,
    )
    return {"message": "logged_in", "token": token}


@fastapi_app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie("token")
    return {"message": "logged_out"}


@fastapi_app.get("/auth/me", response_model=UserOut)
def me(user_id: str = Depends(get_current_user_id)):
    users = db["users"]
    u = users.find_one({"_id": objid(user_id)})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(u["_id"]),
        "name": u.get("name"),
        "username": u.get("username"),
        "avatar": u.get("avatar"),
        "bio": u.get("bio"),
        "last_seen": u.get("last_seen"),
        "online": str(u.get("_id")) in connected_users,
    }


# ----------------------------------------------------------------------------
# Routes: Users
# ----------------------------------------------------------------------------
@fastapi_app.get("/users/search")
def search_users(q: str, user_id: str = Depends(get_current_user_id)):
    users = db["users"]
    cursor = users.find({
        "$and": [
            {"_id": {"$ne": objid(user_id)}},
            {"$or": [
                {"name": {"$regex": q, "$options": "i"}},
                {"username": {"$regex": q, "$options": "i"}},
            ]}
        ]
    }).limit(20)
    results = []
    for u in cursor:
        results.append({
            "id": str(u["_id"]),
            "name": u.get("name"),
            "username": u.get("username"),
            "avatar": u.get("avatar"),
            "online": str(u["_id"]) in connected_users,
        })
    return results


@fastapi_app.get("/users/{userId}")
def get_user(userId: str, user_id: str = Depends(get_current_user_id)):
    users = db["users"]
    u = users.find_one({"_id": objid(userId)})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(u["_id"]),
        "name": u.get("name"),
        "username": u.get("username"),
        "avatar": u.get("avatar"),
        "bio": u.get("bio"),
        "last_seen": u.get("last_seen"),
        "online": str(u["_id"]) in connected_users,
    }


# ----------------------------------------------------------------------------
# Routes: Conversations
# ----------------------------------------------------------------------------
@fastapi_app.get("/conversations")
def get_conversations(user_id: str = Depends(get_current_user_id)):
    convs = db["conversations"]
    msgs = db["messages"]
    cursor = convs.find({"participants": {"$in": [objid(user_id)]}}).sort("updated_at", -1)
    results = []
    for c in cursor:
        last_msg = None
        if c.get("lastMessageId"):
            m = msgs.find_one({"_id": c["lastMessageId"]})
            if m:
                last_msg = {
                    "id": str(m["_id"]),
                    "content": m.get("content"),
                    "created_at": m.get("created_at"),
                }
        results.append({
            "id": str(c["_id"]),
            "isGroup": c.get("isGroup", False),
            "groupName": c.get("groupName"),
            "groupAvatar": c.get("groupAvatar"),
            "participants": [str(pid) for pid in c.get("participants", [])],
            "lastMessage": last_msg,
            "unread": c.get("unread", {}).get(user_id, 0),
            "updated_at": c.get("updated_at"),
        })
    return results


@fastapi_app.post("/conversations")
def create_conversation(body: ConversationCreate, user_id: str = Depends(get_current_user_id)):
    convs = db["conversations"]
    pids: List[ObjectId] = []
    if body.isGroup:
        if not body.participants:
            raise HTTPException(status_code=400, detail="participants required for group")
        pids = [objid(pid) for pid in list(set(body.participants + [user_id]))]
    else:
        if not body.participantId:
            raise HTTPException(status_code=400, detail="participantId required")
        # if exists 1-1, return it
        other = objid(body.participantId)
        existing = convs.find_one({
            "isGroup": False,
            "participants": {"$all": [objid(user_id), other], "$size": 2},
        })
        if existing:
            return {"id": str(existing["_id"]) }
        pids = [objid(user_id), other]

    doc = {
        "participants": pids,
        "isGroup": body.isGroup,
        "groupName": body.groupName if body.isGroup else None,
        "groupAvatar": body.groupAvatar if body.isGroup else None,
        "lastMessageId": None,
        "unread": {},
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = convs.insert_one(doc)
    conv_id = str(res.inserted_id)
    # Notify participants online
    for pid in pids:
        sid = connected_users.get(str(pid))
        if sid:
            # fire and forget
            import anyio
            anyio.from_thread.run(sio.emit, "conversation:new", {"id": conv_id}, to=sid)
    return {"id": conv_id}


# ----------------------------------------------------------------------------
# Routes: Messages
# ----------------------------------------------------------------------------
@fastapi_app.get("/messages/{conversationId}")
def get_messages(conversationId: str, skip: int = 0, limit: int = 30, user_id: str = Depends(get_current_user_id)):
    msgs = db["messages"]
    convs = db["conversations"]
    c = convs.find_one({"_id": objid(conversationId), "participants": {"$in": [objid(user_id)]}})
    if not c:
        raise HTTPException(status_code=404, detail="Conversation not found")
    cursor = (
        msgs.find({"conversationId": objid(conversationId)})
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )
    res = []
    for m in cursor:
        res.append({
            "id": str(m["_id"]),
            "senderId": str(m["senderId"]),
            "content": m.get("content"),
            "attachments": m.get("attachments", []),
            "status": m.get("status", "sent"),
            "created_at": m.get("created_at"),
        })
    return list(reversed(res))


@fastapi_app.post("/messages")
async def send_message(body: MessageCreate, user_id: str = Depends(get_current_user_id)):
    msgs = db["messages"]
    convs = db["conversations"]
    c = convs.find_one({"_id": objid(body.conversationId), "participants": {"$in": [objid(user_id)]}})
    if not c:
        raise HTTPException(status_code=404, detail="Conversation not found")
    msg_doc = {
        "conversationId": objid(body.conversationId),
        "senderId": objid(user_id),
        "content": body.content or "",
        "attachments": body.attachments or [],
        "status": "sent",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = msgs.insert_one(msg_doc)
    msg_id = str(res.inserted_id)
    # update conversation
    convs.update_one({"_id": objid(body.conversationId)}, {"$set": {"lastMessageId": res.inserted_id, "updated_at": datetime.now(timezone.utc)}, "$inc": {f"unread.{user_id}": 0}})

    payload = {
        "id": msg_id,
        "conversationId": body.conversationId,
        "senderId": user_id,
        "content": msg_doc["content"],
        "attachments": msg_doc["attachments"],
        "status": "sent",
        "created_at": msg_doc["created_at"].isoformat(),
    }
    # emit to room
    await sio.emit("message:new", payload, room=body.conversationId)
    return payload


@fastapi_app.post("/messages/read/{conversationId}")
async def mark_read(conversationId: str, user_id: str = Depends(get_current_user_id)):
    msgs = db["messages"]
    convs = db["conversations"]
    convs.update_one({"_id": objid(conversationId)}, {"$set": {f"unread.{user_id}": 0}})
    # mark messages from others as read
    msgs.update_many({"conversationId": objid(conversationId), "senderId": {"$ne": objid(user_id)}}, {"$set": {"status": "read", "updated_at": datetime.now(timezone.utc)}})
    await sio.emit("message:read", {"conversationId": conversationId, "userId": user_id}, room=conversationId)
    return {"ok": True}


# ----------------------------------------------------------------------------
# Socket.IO Events
# ----------------------------------------------------------------------------
@sio.event
async def connect(sid, environ, auth):
    # Expect token in auth or query string
    token = None
    if auth and isinstance(auth, dict):
        token = auth.get("token")
    if token is None:
        # try query string
        qs = environ.get("QUERY_STRING", "")
        # token=... in qs
        for part in qs.split("&"):
            if part.startswith("token="):
                token = part.split("=", 1)[1]
                break
    if not token:
        return False
    try:
        user_id = decode_token(token)
        connected_users[user_id] = sid
        await sio.save_session(sid, {"user_id": user_id})
        # broadcast online status
        await sio.emit("presence:online", {"userId": user_id})
    except Exception:
        return False


@sio.event
async def disconnect(sid):
    sess = await sio.get_session(sid)
    if not sess:
        return
    user_id = sess.get("user_id")
    # remove mapping
    if user_id and connected_users.get(user_id) == sid:
        connected_users.pop(user_id, None)
        await sio.emit("presence:offline", {"userId": user_id})


@sio.event
async def join(sid, data):
    # data: {conversationId}
    conv_id = data.get("conversationId") if isinstance(data, dict) else None
    if conv_id:
        await sio.enter_room(sid, conv_id)


@sio.event
async def typing(sid, data):
    # data: {conversationId, isTyping}
    conv_id = data.get("conversationId")
    is_typing = data.get("isTyping", False)
    sess = await sio.get_session(sid)
    user_id = sess.get("user_id") if sess else None
    if conv_id and user_id:
        await sio.emit("typing", {"conversationId": conv_id, "userId": user_id, "isTyping": is_typing}, room=conv_id, skip_sid=sid)


# Expose ASGI app
app = asgi_app

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
