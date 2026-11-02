from datetime import date, timedelta, datetime, timezone
from uuid import uuid4
import secrets, os, logging, hashlib, json
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from pathlib import Path
from .database import Base, engine, get_db, ensure_compat_schema
from . import models, schemas
from . import enterprise_models
from .security import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    hash_refresh_token, current_user, require_admin, require_roles,
    record_security_event, MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES, REFRESH_DAYS,
)
try:
    from ..chatbot import router as chatbot_router
    from ..prescription_scanner import router as scanner_router
except ImportError:
    from chatbot import router as chatbot_router
    from prescription_scanner import router as scanner_router

logger = logging.getLogger("pharmasys")
Base.metadata.create_all(bind=engine)
ensure_compat_schema()
_production_mode = os.getenv("NODE_ENV", os.getenv("ENVIRONMENT", "development")).strip().lower() == "production"
app = FastAPI(
    title="PharmaSys API", version="2.0.0", description="PharmaSys pharmacy management API",
    docs_url=None if _production_mode else "/docs",
    redoc_url=None if _production_mode else "/redoc",
    openapi_url=None if _production_mode else "/openapi.json",
)

# Frontend is deployed separately. This service exposes API endpoints only.
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:5500,http://127.0.0.1:5500,http://localhost:5501,http://127.0.0.1:5501").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)
# Allow prescription images up to 10 MiB; the scanner enforces its own 10 MiB limit.
MAX_BODY_BYTES = 12 * 1024 * 1024


@app.middleware("http")
async def security_headers_and_limits(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body is too large."})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.include_router(chatbot_router)
app.include_router(scanner_router)

SYNC_MODULES = {"customers","suppliers","purchases","expenses","shifts","delivery","notifications","activity","users","settings","heldSales"}
SYNC_ROLE_ACCESS = {
    "customers": {"admin","pharmacist","cashier"}, "suppliers": {"admin","pharmacist"},
    "purchases": {"admin","pharmacist"}, "expenses": {"admin","pharmacist"},
    "shifts": {"admin","pharmacist","cashier"},
    "delivery": {"admin","pharmacist","cashier","delivery"}, "notifications": {"admin"},
    "activity": {"admin"}, "users": {"admin"}, "settings": {"admin"},
    "heldSales": {"admin","pharmacist","cashier"}
}

def require_sync_access(module, user):
    if module not in SYNC_MODULES: raise HTTPException(400,"Unsupported sync module")
    role = str(getattr(user, "role", "") or "").strip().lower()
    if role not in SYNC_ROLE_ACCESS.get(module, set()): raise HTTPException(403,"Insufficient permissions for this module")

def generate_ean13(db: Session) -> str:
    for _ in range(100):
        body = "200" + "".join(str(secrets.randbelow(10)) for _ in range(9))
        digits = [int(x) for x in body]
        checksum = (10 - (sum(digits[::2]) + 3 * sum(digits[1::2])) % 10) % 10
        code = body + str(checksum)
        if not db.query(models.Product).filter(models.Product.barcode == code, models.Product.active.is_(True)).first(): return code
    raise HTTPException(503, "Could not allocate a unique barcode")

def bootstrap_users(db: Session):
    """Create missing local accounts without resetting existing credentials or roles."""
    production = os.getenv("NODE_ENV", os.getenv("ENVIRONMENT", "development")).lower() == "production"
    admin_username = "admin@pharmasys.local"
    configured_admin_password = (os.getenv("BOOTSTRAP_PASSWORD") or "").strip()

    if production:
        # Disable only untouched demo accounts; do not interfere with accounts whose credentials were changed.
        for demo_username in ("pharmacist@pharmasys.local", "cashier@pharmasys.local", "delivery@pharmasys.local"):
            demo_user = db.query(models.User).filter(models.User.username == demo_username).first()
            if demo_user and verify_password("demo1234", demo_user.password_hash):
                demo_user.active = False
        admin_exists = db.query(models.User).filter(models.User.username == admin_username).first() is not None
        if not admin_exists and (
            len(configured_admin_password) < 12
            or configured_admin_password in {"change-this-before-production", "Pharma@2026", "admin", "password123"}
        ):
            raise RuntimeError("Set a unique BOOTSTRAP_PASSWORD of at least 12 characters before first production startup.")
        # Never create well-known demo pharmacist/cashier/delivery accounts in production.
        accounts = [(admin_username, "مدير النظام", "admin", configured_admin_password)]
    else:
        accounts = [
            (admin_username, "مدير النظام", "admin", configured_admin_password or "Pharma@2026"),
            ("pharmacist@pharmasys.local", "الصيدلي", "pharmacist", "demo1234"),
            ("cashier@pharmasys.local", "الكاشير", "cashier", "demo1234"),
            ("delivery@pharmasys.local", "التوصيل", "delivery", "demo1234"),
        ]

    for username, full_name, role, password in accounts:
        user = db.query(models.User).filter(models.User.username == username).first()
        if user is not None:
            # A restart must not undo a password change, re-enable a disabled account,
            # clear a lockout, or silently restore a role changed by an administrator.
            continue
        if not password or len(password) < 8:
            raise RuntimeError(f"A valid bootstrap password is required to create {username}.")
        user = models.User(
            username=username,
            full_name=full_name,
            password_hash=hash_password(password),
            role=role,
            active=True,
            failed_attempts=0,
            locked_until=None,
            last_failed_login=None,
            password_changed_at=datetime.utcnow(),
        )
        db.add(user)
    db.commit()

def ensure_main_branch(db: Session):
    branch = db.query(models.Branch).filter(models.Branch.code == "MAIN").first()
    if not branch:
        branch = models.Branch(name="الفرع الرئيسي", code="MAIN", address="")
        db.add(branch); db.commit(); db.refresh(branch)
    # Seed existing global product quantities into the main branch once.
    products = db.query(models.Product).filter(models.Product.active == True).all()
    for product in products:
        row = db.query(models.BranchStock).filter_by(branch_id=branch.id, product_id=product.id).first()
        if not row:
            db.add(models.BranchStock(branch_id=branch.id, product_id=product.id, quantity=product.quantity))
    db.commit()
    return branch


@app.on_event("startup")
def startup():
    db=next(get_db())
    try:
        bootstrap_users(db)
        ensure_main_branch(db)
    finally: db.close()

@app.get("/", tags=["System"], include_in_schema=False)
def root():
    return {"name": "PharmaSys API", "version": "2.0.0", "status": "running", "health": "/health"}

@app.get("/health", tags=["System"])
def health(db: Session=Depends(get_db)):
    db.execute(func.now()); return {"status":"ok","database":"connected","version":"2.0.0"}

@app.post("/auth/register", response_model=dict, tags=["Authentication"])
def register(data: schemas.UserCreate, db: Session=Depends(get_db)):
    if db.query(models.User).count(): raise HTTPException(403,"Public registration is closed")
    user=models.User(username=data.username.lower().strip(),full_name=data.full_name,password_hash=hash_password(data.password),role="admin")
    db.add(user); db.commit(); db.refresh(user); return {"id":user.id,"username":user.username,"role":user.role}

LOGIN_WINDOW_SECONDS = 10 * 60
_login_attempts = {}


def _client_ip(request: Request) -> str:
    # Only trust forwarded headers when the deployment explicitly terminates/proxies traffic.
    return request.client.host if request.client else "unknown"


def _rate_limit_login(ip: str):
    now = datetime.utcnow().timestamp()
    bucket = _login_attempts.setdefault(ip, [])
    bucket[:] = [t for t in bucket if now - t < LOGIN_WINDOW_SECONDS]
    if len(bucket) >= 20:
        raise HTTPException(429, "Too many failed login attempts. Try again later.")

def _record_failed_login_ip(ip: str | None):
    if not ip:
        return
    now = datetime.utcnow().timestamp()
    bucket = _login_attempts.setdefault(ip, [])
    bucket[:] = [t for t in bucket if now - t < LOGIN_WINDOW_SECONDS]
    bucket.append(now)


def authenticate(username, password, db: Session, request: Request | None = None):
    username = username.strip().lower()
    ip = _client_ip(request) if request else None
    if ip:
        _rate_limit_login(ip)

    user = db.query(models.User).filter(models.User.username == username).first()
    now = datetime.utcnow()

    if user and user.locked_until and user.locked_until > now:
        raise HTTPException(429, "Account temporarily locked. Try again later.")

    if not user or not user.active or not verify_password(password, user.password_hash):
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            user.last_failed_login = now
            if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                record_security_event(db, "ACCOUNT_LOCKED", "HIGH", "Account locked after repeated failed logins", user.id, {"ip": ip})
            else:
                record_security_event(db, "LOGIN_FAILED", "MEDIUM", "Failed login", user.id, {"ip": ip})
            db.commit()
        else:
            record_security_event(db, "LOGIN_FAILED", "MEDIUM", "Failed login for unknown account", None, {"ip": ip})
            db.commit()
        _record_failed_login_ip(ip)
        raise HTTPException(401, "Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})

    # Successful authentication must not consume the failed-attempt rate-limit bucket.
    if ip:
        _login_attempts.pop(ip, None)
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now

    session_id = secrets.token_urlsafe(32)
    refresh_token = create_refresh_token(user, session_id, 1)
    session = models.SessionToken(
        id=session_id,
        user_id=user.id,
        refresh_token_hash=hash_refresh_token(refresh_token),
        token_version=1,
        device=(request.headers.get("user-agent", "")[:160] if request else None),
        ip=ip,
        expires_at=now + timedelta(days=REFRESH_DAYS),
        last_active_at=now,
    )
    db.add(session)
    record_security_event(db, "LOGIN", "LOW", "Successful login", user.id, {"ip": ip})
    db.commit()

    return {
        "access_token": create_access_token(user, session_id),
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "session_id": session_id,
    }


@app.post("/auth/login", response_model=schemas.Token, tags=["Authentication"])
def login(data: schemas.LoginInput, request: Request, db: Session=Depends(get_db)): return authenticate(data.username,data.password,db,request)

@app.post("/auth/token", response_model=schemas.Token, tags=["Authentication"])
def token_login(form: OAuth2PasswordRequestForm=Depends(), request: Request = None, db: Session=Depends(get_db)): return authenticate(form.username,form.password,db,request)

@app.post("/auth/refresh", response_model=schemas.Token, tags=["Authentication"])
def refresh_token(data: dict, request: Request, db: Session = Depends(get_db)):
    raw = data.get("refresh_token") if isinstance(data, dict) else None
    if not isinstance(raw, str) or len(raw) < 20:
        raise HTTPException(401, "Invalid refresh token")
    from jose import jwt, JWTError
    from .security import SECRET_KEY, ALGORITHM
    try:
        payload = jwt.decode(raw, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"]); sid = payload["sid"]; token_version = int(payload["tv"])
    except (JWTError, KeyError, TypeError, ValueError):
        raise HTTPException(401, "Invalid or expired refresh token")

    session = db.query(models.SessionToken).filter(models.SessionToken.id == sid).with_for_update().first()
    if not session or session.revoked_at is not None or session.expires_at <= datetime.utcnow():
        raise HTTPException(401, "Session is no longer active")

    # Rotation must be atomic. A reused old token revokes every session.
    if session.token_version != token_version or session.refresh_token_hash != hash_refresh_token(raw):
        db.query(models.SessionToken).filter(models.SessionToken.user_id == user_id, models.SessionToken.revoked_at.is_(None)).update(
            {models.SessionToken.revoked_at: datetime.utcnow()}, synchronize_session=False
        )
        record_security_event(db, "REFRESH_REUSE", "CRITICAL", "Refresh-token reuse detected; all sessions revoked", user_id, {"ip": _client_ip(request)})
        db.commit()
        raise HTTPException(401, "Suspicious session detected. Sign in again.")

    user = db.query(models.User).filter(models.User.id == user_id, models.User.active.is_(True)).first()
    if not user:
        raise HTTPException(401, "Account is inactive")

    session.token_version += 1
    new_refresh = create_refresh_token(user, sid, session.token_version)
    session.refresh_token_hash = hash_refresh_token(new_refresh)
    session.last_active_at = datetime.utcnow()
    session.ip = _client_ip(request)
    db.commit()
    return {
        "access_token": create_access_token(user, sid),
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "session_id": sid,
    }


@app.post("/auth/logout", tags=["Authentication"])
def logout(data: dict, user=Depends(current_user), db: Session=Depends(get_db)):
    sid = data.get("session_id") if isinstance(data, dict) else None
    q = db.query(models.SessionToken).filter(models.SessionToken.user_id == user.id, models.SessionToken.revoked_at.is_(None))
    if sid:
        q = q.filter(models.SessionToken.id == sid)
    q.update({models.SessionToken.revoked_at: datetime.utcnow()}, synchronize_session=False)
    db.commit()
    return {"ok": True}


@app.post("/auth/logout-all", tags=["Authentication"])
def logout_all(user=Depends(current_user), db: Session=Depends(get_db)):
    db.query(models.SessionToken).filter(models.SessionToken.user_id == user.id, models.SessionToken.revoked_at.is_(None)).update(
        {models.SessionToken.revoked_at: datetime.utcnow()}, synchronize_session=False
    )
    db.commit()
    return {"ok": True}


@app.get("/auth/sessions", tags=["Authentication"])
def list_sessions(user=Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(models.SessionToken).filter(models.SessionToken.user_id == user.id).order_by(models.SessionToken.created_at.desc()).limit(50).all()
    return {"sessions": [
        {"id": r.id, "device": r.device, "ip": r.ip, "created_at": r.created_at,
         "last_active_at": r.last_active_at, "expires_at": r.expires_at,
         "active": r.revoked_at is None and r.expires_at > datetime.utcnow()}
        for r in rows
    ]}


@app.post("/auth/change-password", tags=["Authentication"])
def change_password(data: schemas.PasswordChange, user=Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(data.current_password, user.password_hash):
        record_security_event(db, "SENSITIVE_ACTION", "HIGH", "Failed password re-authentication", user.id)
        db.commit()
        raise HTTPException(401, "Current password is incorrect.")
    if data.current_password == data.new_password:
        raise HTTPException(400, "New password must be different.")
    user.password_hash = hash_password(data.new_password)
    user.password_changed_at = datetime.utcnow()
    db.query(models.SessionToken).filter(
        models.SessionToken.user_id == user.id,
        models.SessionToken.revoked_at.is_(None)
    ).update({models.SessionToken.revoked_at: datetime.utcnow()}, synchronize_session=False)
    record_security_event(db, "PASSWORD_CHANGED", "HIGH", "Password changed; sessions revoked", user.id)
    db.commit()
    return {"ok": True}


@app.get("/auth/me", tags=["Authentication"])
def me(user=Depends(current_user)): return {"id":user.id,"username":user.username,"full_name":user.full_name,"role":user.role,"status":"active","last_login_at":user.last_login_at}

@app.get("/users", tags=["Users"])
def list_users(db:Session=Depends(get_db), user=Depends(require_admin)):
    return [{"id":u.id,"name":u.full_name,"email":u.username,"role":u.role,"status":"active" if u.active else "inactive","createdAt":u.created_at.isoformat()} for u in db.query(models.User).order_by(models.User.id).all()]

@app.post("/users", tags=["Users"])
def create_user(data: schemas.UserCreate, db: Session=Depends(get_db), user=Depends(require_admin)):
    if data.role not in {"admin", "pharmacist", "cashier", "delivery"}:
        raise HTTPException(400, "Unsupported user role")
    username=data.username.lower().strip()
    if db.query(models.User).filter(models.User.username==username).first():
        raise HTTPException(409, "Username already exists")
    obj=models.User(username=username, full_name=data.full_name, password_hash=hash_password(data.password), role=data.role)
    try:
        db.add(obj)
        db.commit()
        db.refresh(obj)
    except IntegrityError:
        db.rollback()
        # The pre-check above is not enough when two requests arrive together.
        if db.query(models.User).filter(models.User.username == username).first():
            raise HTTPException(409, "Username already exists")
        logger.exception("Database conflict while creating user")
        raise HTTPException(409, "User could not be created because of a database conflict")
    return {"id":obj.id,"name":obj.full_name,"email":obj.username,"role":obj.role,"status":"active"}

@app.post("/categories", response_model=schemas.CategoryOut, tags=["Categories"])
def create_category(data: schemas.CategoryCreate, db:Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist"))):
    # Normalize names consistently and handle the race where two requests pass the pre-check.
    normalized_name = data.name.strip()
    if not normalized_name:
        raise HTTPException(422, "Category name cannot be empty")
    if db.query(models.Category).filter(func.lower(func.trim(models.Category.name)) == normalized_name.lower()).first():
        raise HTTPException(409, "Category already exists")
    payload = data.model_dump()
    payload["name"] = normalized_name
    obj=models.Category(**payload)
    try:
        db.add(obj); db.commit(); db.refresh(obj)
        return obj
    except IntegrityError:
        db.rollback()
        duplicate = db.query(models.Category).filter(func.lower(func.trim(models.Category.name)) == normalized_name.lower()).first()
        if duplicate:
            raise HTTPException(409, "Category already exists")
        raise HTTPException(409, "Category could not be created because of a database conflict")
@app.get("/categories", response_model=list[schemas.CategoryOut], tags=["Categories"])
def list_categories(db:Session=Depends(get_db), user=Depends(current_user)): return db.query(models.Category).order_by(models.Category.name).all()
@app.delete("/categories/{category_id}", tags=["Categories"])
def delete_category(category_id:int,db:Session=Depends(get_db),user=Depends(require_admin)):
    obj=db.get(models.Category,category_id)
    if not obj: raise HTTPException(404,"Category not found")
    if db.query(models.Product).filter_by(category_id=category_id).first(): raise HTTPException(409,"Move or remove products first")
    db.delete(obj); db.commit(); return {"message":"Category deleted"}

@app.post("/products", response_model=schemas.ProductOut, tags=["Products"])
def create_product(data:schemas.ProductCreate,db:Session=Depends(get_db),user=Depends(require_roles("admin","pharmacist"))):
    if data.selling_price < data.purchase_price:
        raise HTTPException(422, "Selling price cannot be lower than purchase price")
    if data.category_id and not db.get(models.Category,data.category_id): raise HTTPException(404,"Category not found")
    if data.barcode and db.query(models.Product).filter(models.Product.barcode == data.barcode, models.Product.active.is_(True)).first(): raise HTTPException(409,"Barcode already exists")
    payload=data.model_dump(); payload["barcode"]=payload.get("barcode") or generate_ean13(db)
    obj=models.Product(**payload)
    try:
        db.add(obj)
        db.flush()
        main = db.query(models.Branch).filter_by(code="MAIN").first()
        if main:
            db.add(models.BranchStock(branch_id=main.id, product_id=obj.id, quantity=data.quantity))
        if data.quantity:
            db.add(models.StockMovement(product_id=obj.id,movement_type="in",quantity=data.quantity,note="Opening stock",user_id=user.id))
        db.commit()
        db.refresh(obj)
        return obj
    except IntegrityError:
        db.rollback()
        barcode_value = payload.get("barcode")
        if barcode_value and db.query(models.Product).filter(models.Product.barcode == barcode_value).first():
            raise HTTPException(409, "Barcode already exists")
        logger.exception("Database conflict while creating product")
        raise HTTPException(409, "Product could not be created because of a database conflict")
@app.get("/products", response_model=list[schemas.ProductOut], tags=["Products"])
def list_products(search:str|None=None,category_id:int|None=None,low_stock:bool=False,skip:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=100),db:Session=Depends(get_db),user=Depends(current_user)):
    q=db.query(models.Product).filter(models.Product.active==True)
    if search: q=q.filter((models.Product.name.ilike(f"%{search}%")) | (models.Product.barcode.ilike(f"%{search}%")))
    if category_id: q=q.filter(models.Product.category_id==category_id)
    if low_stock: q=q.filter(models.Product.quantity<=models.Product.reorder_level)
    return q.order_by(models.Product.name).offset(skip).limit(limit).all()
@app.get("/products/barcode/{barcode}",response_model=schemas.ProductOut,tags=["Products"])
def barcode(barcode:str,db:Session=Depends(get_db),user=Depends(current_user)):
    obj=db.query(models.Product).filter(models.Product.barcode==barcode,models.Product.active==True).first()
    if not obj: raise HTTPException(404,"No active product matches this barcode")
    return obj
@app.get("/products/{product_id}",response_model=schemas.ProductOut,tags=["Products"])
def get_product(product_id:int,db:Session=Depends(get_db),user=Depends(current_user)):
    obj=db.get(models.Product,product_id)
    if not obj or not obj.active: raise HTTPException(404,"Product not found")
    return obj
@app.patch("/products/{product_id}",response_model=schemas.ProductOut,tags=["Products"])
def update_product(product_id:int,data:schemas.ProductUpdate,db:Session=Depends(get_db),user=Depends(require_roles("admin","pharmacist"))):
    obj=db.get(models.Product,product_id)
    if not obj: raise HTTPException(404,"Product not found")
    changes=data.model_dump(exclude_unset=True)
    if "category_id" in changes and changes["category_id"] and not db.get(models.Category,changes["category_id"]): raise HTTPException(404,"Category not found")
    if "barcode" in changes and changes["barcode"]:
        dup=db.query(models.Product).filter(models.Product.barcode==changes["barcode"],models.Product.id!=product_id,models.Product.active.is_(True)).first()
        if dup: raise HTTPException(409,"Barcode already exists")
    new_purchase = changes.get("purchase_price", obj.purchase_price)
    new_selling = changes.get("selling_price", obj.selling_price)
    if ("purchase_price" in changes or "selling_price" in changes) and new_selling < new_purchase:
        raise HTTPException(422, "Selling price cannot be lower than purchase price")
    for k,v in changes.items(): setattr(obj,k,v)
    try:
        db.commit()
        db.refresh(obj)
        return obj
    except IntegrityError:
        db.rollback()
        barcode_value = changes.get("barcode")
        if barcode_value and db.query(models.Product).filter(
            models.Product.barcode == barcode_value, models.Product.id != product_id
        ).first():
            raise HTTPException(409, "Barcode already exists")
        logger.exception("Database conflict while updating product id=%s", product_id)
        raise HTTPException(409, "Product could not be updated because of a database conflict")
@app.delete("/products/{product_id}",tags=["Products"])
def deactivate_product(product_id:int,db:Session=Depends(get_db),user=Depends(require_roles("admin", "pharmacist"))):
    obj=db.get(models.Product,product_id)
    if not obj: raise HTTPException(404,"Product not found")
    # Release the unique active barcode for reuse while preserving it for audit/history.
    if obj.barcode:
        obj.archived_barcode = obj.barcode
        obj.barcode = None
    obj.active=False
    db.commit()
    return {"message":"Product archived","archived_barcode":obj.archived_barcode}

@app.post("/products/{product_id}/stock", tags=["Inventory"])
def change_stock(product_id: int, data: schemas.StockChange, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    """Apply a manual stock movement atomically while serializing concurrent updates."""
    if data.movement_type not in ("in", "out"):
        raise HTTPException(400, "movement_type must be in or out")
    try:
        obj = db.query(models.Product).filter_by(id=product_id).with_for_update().first()
        if not obj or not obj.active:
            raise HTTPException(404, "Product not found")
        new_quantity = int(obj.quantity) + data.quantity if data.movement_type == "in" else int(obj.quantity) - data.quantity
        if new_quantity < 0:
            raise HTTPException(409, "Insufficient stock")
        obj.quantity = new_quantity
        main = db.query(models.Branch).filter_by(code="MAIN").first()
        if main:
            bs = db.query(models.BranchStock).filter_by(branch_id=main.id, product_id=product_id).with_for_update().first()
            if bs is None:
                bs = models.BranchStock(branch_id=main.id, product_id=product_id, quantity=new_quantity)
                db.add(bs)
            else:
                bs.quantity = new_quantity
        db.add(models.StockMovement(product_id=product_id, movement_type=data.movement_type,
                                    quantity=data.quantity, note=data.note, user_id=user.id))
        db.commit()
        db.refresh(obj)
        return {"product_id": product_id, "quantity": obj.quantity}
    except Exception:
        db.rollback()
        raise
@app.post("/inventory/stock-batch", tags=["Inventory"])
def change_stock_batch(data: schemas.StockBatchChange, db: Session = Depends(get_db), user=Depends(current_user)):
    """Atomically apply a group of return/cancellation stock movements with retry protection."""
    role = str(getattr(user, "role", "") or "").strip().lower()
    if role not in {"admin", "pharmacist", "cashier"}:
        raise HTTPException(403, "Insufficient permissions")
    # This low-level endpoint is intentionally restricted. Cashier returns must use
    # /sales/{sale_id}/returns so the backend validates the original invoice and quantity.
    if role not in {"admin", "pharmacist"}:
        raise HTTPException(403, "Use the validated sale-return endpoint for cashier returns")
    for movement in data.movements:
        if movement.movement_type != "in":
            raise HTTPException(400, "Stock batch accepts stock-in movements only")

    operation_hash = hashlib.sha256(data.operation_id.encode()).hexdigest()
    key = f"sb:{user.id}:{operation_hash}"
    fingerprint = hashlib.sha256(json.dumps([m.model_dump() for m in data.movements], sort_keys=True).encode()).hexdigest()
    existing = db.query(models.SyncRecord).filter_by(module="stock-batch", record_id=key, user_id=user.id).first()
    if existing:
        if (existing.payload or {}).get("fingerprint") != fingerprint:
            raise HTTPException(409, "Idempotency key was already used with a different payload")
        return (existing.payload or {}).get("response", existing.payload)

    results = []
    try:
        for movement in data.movements:
            product = db.query(models.Product).filter_by(id=movement.product_id).with_for_update().first()
            if not product or not product.active:
                raise HTTPException(404, f"Product {movement.product_id} not found")
            product.quantity += movement.quantity
            main = db.query(models.Branch).filter_by(code="MAIN").first()
            if main:
                branch_stock = db.query(models.BranchStock).filter_by(branch_id=main.id, product_id=product.id).with_for_update().first()
                if not branch_stock:
                    db.add(models.BranchStock(branch_id=main.id, product_id=product.id, quantity=max(0, product.quantity - movement.quantity)))
                    db.flush()
                    branch_stock = db.query(models.BranchStock).filter_by(branch_id=main.id, product_id=product.id).with_for_update().first()
                if branch_stock is not None:
                    branch_stock.quantity += movement.quantity
            db.add(models.StockMovement(product_id=product.id, movement_type="in", quantity=movement.quantity,
                                        note=movement.note, user_id=user.id))
            results.append({"product_id": product.id, "quantity": product.quantity})
        response_payload = {"ok": True, "operation_id": data.operation_id, "items": results}
        payload = {"fingerprint": fingerprint, "response": response_payload}
        db.add(models.SyncRecord(module="stock-batch", record_id=key, user_id=user.id, payload=payload))
        db.commit()
        return response_payload
    except Exception:
        db.rollback()
        raise

@app.get("/inventory/movements",tags=["Inventory"])
def movements(product_id:int|None=None,db:Session=Depends(get_db),user=Depends(require_roles("admin", "pharmacist"))):
    q=db.query(models.StockMovement)
    if product_id:q=q.filter_by(product_id=product_id)
    return [{"id":m.id,"product_id":m.product_id,"type":m.movement_type,"quantity":m.quantity,"note":m.note,"created_at":m.created_at} for m in q.order_by(models.StockMovement.created_at.desc()).limit(500)]

@app.post("/sales", response_model=schemas.SaleOut, tags=["Sales"])
def create_sale(data: schemas.SaleCreate, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist", "cashier"))):
    # Idempotency must be checked BEFORE stock validation. A retry of an already
    # committed invoice must return the original sale even if stock has since changed.
    scoped_reference = f"u{user.id}:{data.client_reference}" if data.client_reference else None
    # expected_unit_price is a preflight guard, not part of the sale's identity. Excluding
    # it keeps retries from older clients idempotent while the committed sale is returned.
    hash_payload = data.model_dump(exclude={"client_reference"})
    for line in hash_payload.get("items", []):
        line.pop("expected_unit_price", None)
    request_hash = hashlib.sha256(json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if scoped_reference:
        existing = db.query(models.Sale).filter(models.Sale.client_reference == scoped_reference).first()
        if existing:
            if existing.request_hash and existing.request_hash != request_hash:
                raise HTTPException(409, "Idempotency key was already used for a different sale")
            # Older invoices have no stored request hash; do not silently reuse their keys for a new payload.
            if not existing.request_hash:
                raise HTTPException(409, "This idempotency key belongs to a legacy sale; use a new key")
            return existing

    main = db.query(models.Branch).filter_by(code="MAIN", active=True).first()
    branch_id = data.branch_id or (main.id if main else None)
    branch = db.get(models.Branch, branch_id) if branch_id else None
    if not branch or not branch.active:
        raise HTTPException(400, "A valid active branch is required for the sale")
    quantities = {}
    for line in data.items:
        quantities[line.product_id] = quantities.get(line.product_id, 0) + line.quantity

    # Lock every affected product row before checking/decrementing stock.
    products = {}
    for pid, qty in quantities.items():
        p = db.query(models.Product).filter(
            models.Product.id == pid,
            models.Product.active.is_(True)
        ).with_for_update().first()
        if not p:
            raise HTTPException(404, f"Product {pid} not found")
        if p.expiry_date is not None and p.expiry_date < date.today():
            raise HTTPException(409, f"Cannot sell expired product {p.name} (expiry date: {p.expiry_date.isoformat()})")
        expected_prices = [line.expected_unit_price for line in data.items if line.product_id == pid and line.expected_unit_price is not None]
        if expected_prices and any(abs(float(price) - float(p.selling_price)) > 0.005 for price in expected_prices):
            raise HTTPException(409, f"Price changed for {p.name}; refresh product prices and confirm the invoice again")
        branch_stock = db.query(models.BranchStock).filter_by(branch_id=branch.id, product_id=pid).with_for_update().first()
        available = branch_stock.quantity if branch_stock else (p.quantity if branch.code == "MAIN" else 0)
        if available < qty:
            raise HTTPException(409, f"Insufficient stock in branch {branch.name} for {p.name}; available: {available}")
        products[pid] = p

    subtotal = sum(float(products[pid].selling_price) * qty for pid, qty in quantities.items())
    if data.discount > subtotal:
        raise HTTPException(400, "Discount cannot exceed subtotal")

    try:
        sale = models.Sale(
            invoice_number="INV-" + uuid4().hex[:12].upper(),
            client_reference=scoped_reference,
            request_hash=request_hash,
            branch_id=branch.id,
            subtotal=subtotal,
            discount=data.discount,
            total=subtotal - data.discount,
            payment_method=data.payment_method,
            customer_name=data.customer_name,
            user_id=user.id,
        )
        db.add(sale)
        db.flush()

        for pid, qty in quantities.items():
            p = products[pid]
            branch_stock = db.query(models.BranchStock).filter_by(branch_id=branch.id, product_id=pid).with_for_update().first()
            if branch_stock is None:
                branch_stock = models.BranchStock(branch_id=branch.id, product_id=pid, quantity=p.quantity if branch.code == "MAIN" else 0)
                db.add(branch_stock); db.flush()
            if branch_stock.quantity < qty:
                raise HTTPException(409, f"Insufficient stock in branch {branch.name} for {p.name}")
            previous = branch_stock.quantity
            branch_stock.quantity -= qty
            if branch.code == "MAIN": p.quantity -= qty
            db.add(models.SaleItem(
                sale_id=sale.id, product_id=pid, product_name=p.name,
                quantity=qty, unit_price=p.selling_price,
                line_total=p.selling_price * qty
            ))
            db.add(models.StockMovement(
                product_id=pid, movement_type="out", quantity=qty,
                note=f"Sale {sale.invoice_number} ({previous}->{p.quantity})",
                user_id=user.id
            ))
        db.commit()
        db.refresh(sale)
        return sale
    except IntegrityError:
        db.rollback()
        if scoped_reference:
            existing = db.query(models.Sale).filter(models.Sale.client_reference == scoped_reference).first()
            if existing:
                if existing.request_hash == request_hash:
                    return existing
                raise HTTPException(409, "Idempotency key was concurrently used for a different sale")
        raise
    except Exception:
        db.rollback()
        raise


@app.post("/sales/{sale_id}/returns", tags=["Sales Returns"])
def create_sale_return(sale_id: int, data: schemas.SaleReturnCreate, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist", "cashier"))):
    """Validate a return against the persisted invoice and apply stock + ledger changes atomically."""
    op_id = f"u{user.id}:r:{hashlib.sha256(data.operation_id.encode()).hexdigest()}"
    request_hash = hashlib.sha256(json.dumps({"sale_id": sale_id, "payload": data.model_dump()}, sort_keys=True).encode()).hexdigest()
    legacy_hash = hashlib.sha256(json.dumps(data.model_dump(), sort_keys=True).encode()).hexdigest()
    existing = db.query(models.SaleReturn).filter_by(operation_id=op_id).first()
    if existing:
        if existing.sale_id != sale_id or existing.request_hash not in {request_hash, legacy_hash}:
            raise HTTPException(409, "Return idempotency key reused with a different invoice or payload")
        return {"ok": True, "id": existing.id, "return_number": existing.return_number, "total_amount": existing.total_amount, "status": existing.sale.status}
    sale = db.query(models.Sale).filter_by(id=sale_id).with_for_update().first()
    if not sale: raise HTTPException(404, "Invoice not found")
    if sale.status == "cancelled": raise HTTPException(409, "Cannot return a cancelled invoice")
    if not data.items: raise HTTPException(400, "At least one return item is required")
    requested = {}
    for line in data.items: requested[line.product_id] = requested.get(line.product_id, 0) + line.quantity
    sale_items = db.query(models.SaleItem).filter_by(sale_id=sale.id).with_for_update().all()
    by_product = {i.product_id: i for i in sale_items}
    for pid, qty in requested.items():
        item = by_product.get(pid)
        if not item: raise HTTPException(400, f"Product {pid} is not on this invoice")
        if item.returned_quantity + qty > item.quantity: raise HTTPException(409, f"Return quantity exceeds invoice quantity for product {pid}")
    ret = models.SaleReturn(operation_id=op_id, request_hash=request_hash, return_number="RET-" + uuid4().hex[:12].upper(), sale_id=sale.id, user_id=user.id, reason=data.reason, notes=data.notes, total_amount=0, kind="return")
    total = 0.0
    try:
        db.add(ret); db.flush()
        sale_branch = db.get(models.Branch, sale.branch_id) if sale.branch_id else db.query(models.Branch).filter_by(code="MAIN").first()
        if not sale_branch:
            raise HTTPException(409, "The invoice has no valid branch; reconcile it before returning stock")
        for pid, qty in requested.items():
            item = by_product[pid]
            product = db.query(models.Product).filter_by(id=pid).with_for_update().first()
            if not product: raise HTTPException(404, f"Product {pid} not found")
            item.returned_quantity += qty
            bs = db.query(models.BranchStock).filter_by(branch_id=sale_branch.id, product_id=pid).with_for_update().first()
            if bs is None:
                bs = models.BranchStock(branch_id=sale_branch.id, product_id=pid, quantity=0); db.add(bs); db.flush()
            bs.quantity += qty
            if sale_branch.code == "MAIN": product.quantity += qty
            # Refund the discounted amount actually paid for this line, not its pre-discount gross.
            gross_line = float(item.line_total or (float(item.unit_price) * item.quantity))
            discount_share = (float(sale.discount or 0) * gross_line / float(sale.subtotal)) if float(sale.subtotal or 0) > 0 else 0.0
            net_line = max(0.0, gross_line - discount_share)
            before_qty = int(item.returned_quantity) - qty
            after_qty = int(item.returned_quantity)
            before_amount = round(net_line * before_qty / max(1, int(item.quantity)), 2)
            after_amount = round(net_line * after_qty / max(1, int(item.quantity)), 2)
            line_total = max(0.0, after_amount - before_amount)
            total += line_total
            effective_unit = round(net_line / max(1, int(item.quantity)), 6)
            db.add(models.SaleReturnItem(sale_return_id=ret.id, sale_item_id=item.id, product_id=pid, quantity=qty, unit_price=effective_unit, line_total=line_total))
            db.add(models.StockMovement(product_id=pid, movement_type="in", quantity=qty, note=f"Return {ret.return_number} for {sale.invoice_number}", user_id=user.id))
        ret.total_amount = round(total, 2)
        if all(i.returned_quantity >= i.quantity for i in sale_items): sale.status = "returned"
        else: sale.status = "partially_returned"
        db.commit(); db.refresh(ret)
        return {"ok": True, "id": ret.id, "return_number": ret.return_number, "total_amount": ret.total_amount, "status": sale.status}
    except IntegrityError:
        db.rollback()
        existing = db.query(models.SaleReturn).filter_by(operation_id=op_id).first()
        if existing and existing.sale_id == sale_id and existing.request_hash == request_hash:
            return {"ok": True, "id": existing.id, "return_number": existing.return_number, "total_amount": existing.total_amount, "status": existing.sale.status}
        if existing:
            raise HTTPException(409, "Return idempotency key was concurrently reused with different data")
        raise
    except Exception:
        db.rollback(); raise

@app.post("/sales/{sale_id}/cancel", tags=["Sales Returns"])
def cancel_sale(sale_id: int, data: schemas.SaleCancelCreate, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist", "cashier"))):
    op_id = f"u{user.id}:c:{hashlib.sha256(data.operation_id.encode()).hexdigest()}"
    request_hash = hashlib.sha256(json.dumps({"sale_id": sale_id, "payload": data.model_dump()}, sort_keys=True).encode()).hexdigest()
    legacy_hash = hashlib.sha256(json.dumps(data.model_dump(), sort_keys=True).encode()).hexdigest()
    existing = db.query(models.SaleReturn).filter_by(operation_id=op_id).first()
    if existing:
        if existing.sale_id != sale_id or existing.request_hash not in {request_hash, legacy_hash}:
            raise HTTPException(409, "Cancellation idempotency key reused with a different invoice or payload")
        return {"ok": True, "id": existing.id, "return_number": existing.return_number, "total_amount": existing.total_amount, "status": "cancelled"}
    sale = db.query(models.Sale).filter_by(id=sale_id).with_for_update().first()
    if not sale: raise HTTPException(404, "Invoice not found")
    if sale.status == "cancelled": raise HTTPException(409, "Invoice is already cancelled")
    if sale.status == "returned": raise HTTPException(409, "Invoice is already fully returned; it cannot also be cancelled")
    sale_items = db.query(models.SaleItem).filter_by(sale_id=sale.id).with_for_update().all()
    ret = models.SaleReturn(operation_id=op_id, request_hash=request_hash, return_number="CAN-" + uuid4().hex[:12].upper(), sale_id=sale.id, user_id=user.id, reason=data.reason, notes=data.notes, total_amount=0, kind="cancellation")
    total=0.0
    try:
        db.add(ret); db.flush()
        sale_branch = db.get(models.Branch, sale.branch_id) if sale.branch_id else db.query(models.Branch).filter_by(code="MAIN").first()
        if not sale_branch: raise HTTPException(409, "The invoice has no valid branch; reconcile it before cancellation")
        for item in sale_items:
            remaining = max(0, item.quantity - item.returned_quantity)
            if remaining <= 0: continue
            product = db.query(models.Product).filter_by(id=item.product_id).with_for_update().first()
            if not product: raise HTTPException(404, f"Product {item.product_id} not found")
            item.returned_quantity += remaining
            bs = db.query(models.BranchStock).filter_by(branch_id=sale_branch.id, product_id=product.id).with_for_update().first()
            if bs is None:
                bs = models.BranchStock(branch_id=sale_branch.id, product_id=product.id, quantity=0); db.add(bs); db.flush()
            bs.quantity += remaining
            if sale_branch.code == "MAIN": product.quantity += remaining
            gross_line = float(item.line_total or (float(item.unit_price) * item.quantity))
            discount_share = (float(sale.discount or 0) * gross_line / float(sale.subtotal)) if float(sale.subtotal or 0) > 0 else 0.0
            net_line = max(0.0, gross_line - discount_share)
            returned_before_cancel = max(0, int(item.returned_quantity) - remaining)
            before_amount = round(net_line * returned_before_cancel / max(1, int(item.quantity)), 2)
            line_total = max(0.0, round(net_line, 2) - before_amount)
            total += line_total
            effective_unit = round(net_line / max(1, int(item.quantity)), 6)
            db.add(models.SaleReturnItem(sale_return_id=ret.id, sale_item_id=item.id, product_id=product.id, quantity=remaining, unit_price=effective_unit, line_total=line_total))
            db.add(models.StockMovement(product_id=product.id, movement_type="in", quantity=remaining, note=f"Invoice cancellation {ret.return_number} for {sale.invoice_number}", user_id=user.id))
        ret.total_amount = round(total, 2); ret.kind = "cancellation"; sale.status = "cancelled"
        db.commit(); db.refresh(ret)
        return {"ok": True, "id": ret.id, "return_number": ret.return_number, "total_amount": ret.total_amount, "status": "cancelled"}
    except IntegrityError:
        db.rollback()
        existing = db.query(models.SaleReturn).filter_by(operation_id=op_id).first()
        if existing and existing.sale_id == sale_id and existing.request_hash == request_hash:
            return {"ok": True, "id": existing.id, "return_number": existing.return_number, "total_amount": existing.total_amount, "status": "cancelled"}
        if existing:
            raise HTTPException(409, "Cancellation idempotency key was concurrently reused with different data")
        raise
    except Exception:
        db.rollback(); raise

@app.get("/sales",response_model=list[schemas.SaleOut],tags=["Sales"])
def list_sales(skip:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=100),db:Session=Depends(get_db),user=Depends(require_roles("admin", "pharmacist", "cashier"))): return db.query(models.Sale).order_by(models.Sale.created_at.desc()).offset(skip).limit(limit).all()
@app.get("/sales/{sale_id}",response_model=schemas.SaleOut,tags=["Sales"])
def get_sale(sale_id:int,db:Session=Depends(get_db),user=Depends(require_roles("admin", "pharmacist", "cashier"))):
    sale=db.get(models.Sale,sale_id)
    if not sale: raise HTTPException(404,"Invoice not found")
    return sale

DELIVERY_STATUSES = {"pending", "preparing", "assigned", "out_for_delivery", "delivered", "cancelled", "failed"}

def _delivery_out(o):
    return {
        "id": o.id, "order_number": o.order_number, "customer_name": o.customer_name,
        "phone": o.phone, "address": o.address, "items": o.items or [],
        "items_total": o.items_total, "delivery_fee": o.delivery_fee, "total": o.total,
        "cod": o.cod, "status": o.status, "driver_id": o.driver_id, "sale_id": getattr(o, "sale_id", None),
        "driver_name": o.driver.full_name if o.driver else None, "notes": o.notes,
        "created_at": o.created_at, "updated_at": o.updated_at
    }

@app.get("/delivery/orders", response_model=list[schemas.DeliveryOrderOut], tags=["Delivery"])
def list_delivery_orders(status: str|None=None, db: Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist","cashier","delivery"))):
    q=db.query(models.DeliveryOrder)
    if user.role == "delivery": q=q.filter(models.DeliveryOrder.driver_id==user.id)
    if status:
        if status not in DELIVERY_STATUSES: raise HTTPException(400, "Invalid delivery status")
        q=q.filter(models.DeliveryOrder.status==status)
    return [_delivery_out(o) for o in q.order_by(models.DeliveryOrder.created_at.desc()).all()]

@app.post("/delivery/orders", response_model=schemas.DeliveryOrderOut, tags=["Delivery"])
def create_delivery_order(data: schemas.DeliveryOrderCreate, db: Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist","cashier"))):
    if data.driver_id:
        driver=db.get(models.User,data.driver_id)
        if not driver or not driver.active or driver.role != "delivery": raise HTTPException(400, "Invalid delivery driver")
    # Prefer a persisted invoice as the trusted source of products and prices.
    if data.sale_id is not None:
        sale = db.query(models.Sale).filter_by(id=data.sale_id).with_for_update().first()
        if not sale: raise HTTPException(404, "Invoice not found")
        if sale.status in {"cancelled", "returned"}: raise HTTPException(409, "Cannot create delivery for a cancelled or fully returned invoice")
        invoice_items = []
        items_total = 0.0
        for sale_item in sale.items:
            remaining_qty = max(0, int(sale_item.quantity) - int(sale_item.returned_quantity or 0))
            if remaining_qty <= 0:
                continue
            gross_line = float(sale_item.line_total or (float(sale_item.unit_price) * sale_item.quantity))
            discount_share = (float(sale.discount or 0) * gross_line / float(sale.subtotal)) if float(sale.subtotal or 0) > 0 else 0.0
            net_line = max(0.0, gross_line - discount_share)
            remaining_total = round(net_line * remaining_qty / max(1, int(sale_item.quantity)), 2)
            invoice_items.append({"product_id": sale_item.product_id, "quantity": remaining_qty, "product_name": sale_item.product_name, "unit_price": round(remaining_total / remaining_qty, 6), "line_total": remaining_total})
            items_total += remaining_total
        items_total = round(items_total, 2)
        if not invoice_items:
            raise HTTPException(409, "No unreturned invoice items remain for delivery")
        if data.items:
            requested = sorted((i.product_id, i.quantity) for i in data.items)
            invoiced = sorted((i["product_id"], i["quantity"]) for i in invoice_items)
            if requested != invoiced: raise HTTPException(422, "Delivery items must match the remaining unreturned invoice quantities")
    else:
        if not data.items: raise HTTPException(422, "Provide a valid sale_id or at least one product item")
        invoice_items=[]; items_total=0.0
        aggregated={}
        for item in data.items: aggregated[item.product_id]=aggregated.get(item.product_id,0)+item.quantity
        for pid, qty in aggregated.items():
            product=db.query(models.Product).filter_by(id=pid, active=True).first()
            if not product: raise HTTPException(404, f"Active product {pid} not found")
            unit_price=float(product.selling_price); line_total=round(unit_price*qty,2)
            invoice_items.append({"product_id":pid,"quantity":qty,"product_name":product.name,"unit_price":unit_price,"line_total":line_total})
            items_total += line_total
        items_total=round(items_total,2)
    if data.sale_id is not None:
        duplicate = db.query(models.DeliveryOrder).filter(
            models.DeliveryOrder.sale_id == data.sale_id,
            models.DeliveryOrder.status.notin_(["cancelled", "failed"])
        ).with_for_update().first()
        if duplicate:
            raise HTTPException(409, f"Invoice already has an active/completed delivery order: {duplicate.order_number}")
        # A fully returned invoice must not be sent for delivery.
        sale_status = db.query(models.Sale.status).filter(models.Sale.id == data.sale_id).scalar()
        if sale_status == "returned":
            raise HTTPException(409, "Cannot deliver a fully returned invoice")
    total=round(items_total + float(data.delivery_fee),2)
    obj=models.DeliveryOrder(order_number="DEL-"+uuid4().hex[:10].upper(), customer_name=data.customer_name, phone=data.phone, address=data.address, items=invoice_items, items_total=items_total, delivery_fee=data.delivery_fee, total=total, cod=data.cod, status="assigned" if data.driver_id else "pending", driver_id=data.driver_id, notes=data.notes, sale_id=data.sale_id, active_sale_id=data.sale_id, created_by=user.id)
    try:
        db.add(obj); db.commit(); db.refresh(obj); return _delivery_out(obj)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A delivery order for this invoice was created concurrently")
    except Exception:
        db.rollback(); raise

@app.patch("/delivery/orders/{order_id}", response_model=schemas.DeliveryOrderOut, tags=["Delivery"])
def update_delivery_order(order_id:int, data: schemas.DeliveryStatusUpdate, db: Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist","cashier","delivery"))):
    if data.status not in DELIVERY_STATUSES: raise HTTPException(400, "Invalid delivery status")
    obj=db.query(models.DeliveryOrder).filter_by(id=order_id).with_for_update().first()
    if not obj: raise HTTPException(404,"Delivery order not found")
    transitions = {
        "pending": {"preparing", "assigned", "cancelled"},
        "preparing": {"assigned", "cancelled"},
        "assigned": {"out_for_delivery", "cancelled", "failed"},
        "out_for_delivery": {"delivered", "failed"},
        "failed": {"pending", "assigned", "cancelled"},
        "delivered": set(),
        "cancelled": set(),
    }
    if data.status != obj.status and data.status not in transitions.get(obj.status, set()):
        raise HTTPException(409, f"Invalid delivery transition: {obj.status} -> {data.status}")
    if user.role == "delivery":
        if obj.driver_id != user.id: raise HTTPException(403,"You can only update your assigned deliveries")
        if data.driver_id not in (None, user.id): raise HTTPException(403,"You cannot reassign deliveries")
        if data.status not in {"out_for_delivery","delivered","failed"}: raise HTTPException(403,"Driver can only update delivery progress")
    requested_status = data.status
    if data.driver_id is not None:
        if obj.status in {"delivered", "cancelled"} and data.driver_id != obj.driver_id:
            raise HTTPException(409, "A completed/cancelled delivery cannot be reassigned")
        if user.role not in {"admin", "pharmacist", "cashier"}: raise HTTPException(403,"Only staff can assign a driver")
        driver=db.get(models.User,data.driver_id)
        if not driver or not driver.active or driver.role != "delivery": raise HTTPException(400,"Invalid delivery driver")
        obj.driver_id=data.driver_id
        if obj.status == "pending" and requested_status == "pending":
            requested_status = "assigned"
    obj.status=requested_status
    if requested_status in {"cancelled", "failed"}:
        obj.active_sale_id = None
    elif requested_status in {"pending", "preparing", "assigned", "out_for_delivery", "delivered"} and obj.sale_id is not None:
        obj.active_sale_id = obj.sale_id
    try:
        db.commit(); db.refresh(obj); return _delivery_out(obj)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Another delivery order already owns this invoice")
    except Exception:
        db.rollback(); raise

# Purchase invoices are persisted with stock, movement, and price-history changes in one transaction.
@app.post("/purchases", tags=["Purchases"])
def create_purchase(data: schemas.PurchaseCreate, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    record_id = f"u{user.id}:purchases:{data.purchase_number}"
    payload_hash = hashlib.sha256(json.dumps(data.model_dump(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    existing = db.query(models.SyncRecord).filter_by(module="purchases", record_id=record_id, user_id=user.id).first()
    if existing:
        saved_hash = (existing.payload or {}).get("_request_hash")
        if saved_hash != payload_hash:
            raise HTTPException(409, "Purchase number already used with different contents")
        return {k:v for k,v in existing.payload.items() if k != "_request_hash"}

    # Supplier records sync asynchronously in the UI. Persist the invoice's supplier snapshot
    # even when that generic supplier record has not arrived yet; prices/stock still come from server products.

    main_branch = db.query(models.Branch).filter_by(code="MAIN", active=True).first()
    if not main_branch:
        raise HTTPException(409, "Main branch is not configured")
    quantities = {}
    for line in data.items:
        quantities[line.product_id] = quantities.get(line.product_id, 0) + line.quantity
    products = {}
    for pid in quantities:
        product = db.query(models.Product).filter_by(id=pid, active=True).with_for_update().first()
        if not product:
            raise HTTPException(404, f"Active product {pid} not found")
        products[pid] = product
    for line in data.items:
        product = products[line.product_id]
        if float(line.purchase_price) > float(product.selling_price):
            raise HTTPException(409, f"Purchase price for {product.name} exceeds its current selling price; update pricing or obtain an approved loss-margin override before receiving stock")
    subtotal = round(sum(line.quantity * line.purchase_price for line in data.items), 2)
    if data.discount > subtotal:
        raise HTTPException(422, "Discount cannot exceed purchase subtotal")
    items_out=[]
    try:
        for line in data.items:
            product=products[line.product_id]
            bs=db.query(models.BranchStock).filter_by(branch_id=main_branch.id, product_id=product.id).with_for_update().first()
            if bs is None:
                bs=models.BranchStock(branch_id=main_branch.id, product_id=product.id, quantity=product.quantity or 0)
                db.add(bs); db.flush()
            previous=int(bs.quantity or 0); bs.quantity=previous+line.quantity
            product.quantity=int(product.quantity or 0)+line.quantity
            product.purchase_price=line.purchase_price
            line_total=round(line.quantity*line.purchase_price,2)
            db.add(models.StockMovement(product_id=product.id, movement_type="in", quantity=line.quantity, note=f"Purchase {data.purchase_number}", user_id=user.id))
            db.add(models.PurchasePriceHistory(product_id=product.id, supplier_id=data.supplier_id, supplier_name=data.supplier_name, purchase_number=data.purchase_number, unit_price=line.purchase_price, quantity=line.quantity, total_cost=line_total))
            items_out.append({"product_id":product.id,"product_name":product.name,"quantity":line.quantity,"purchase_price":line.purchase_price,"line_total":line_total})
        result={"purchase_number":data.purchase_number,"supplier_id":data.supplier_id,"supplier_name":data.supplier_name,"items":items_out,"subtotal":subtotal,"discount":data.discount,"total":round(subtotal-data.discount,2),"created_at":datetime.utcnow().isoformat()}
        stored={**result,"_request_hash":payload_hash}
        db.add(models.SyncRecord(module="purchases",record_id=record_id,user_id=user.id,payload=stored))
        db.commit()
        return result
    except IntegrityError:
        db.rollback()
        existing = db.query(models.SyncRecord).filter_by(module="purchases", record_id=record_id, user_id=user.id).first()
        if existing:
            if (existing.payload or {}).get("_request_hash") == payload_hash:
                return {k:v for k,v in existing.payload.items() if k != "_request_hash"}
            raise HTTPException(409, "Purchase number concurrently used with different contents")
        raise
    except HTTPException:
        db.rollback(); raise
    except Exception:
        db.rollback(); raise

# ---------------- Advanced purchasing / valuation ----------------
@app.get("/products/{product_id}/purchase-price-history", response_model=list[schemas.PurchasePriceHistoryOut], tags=["Purchases"])
def product_purchase_price_history(product_id: int, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    product = db.get(models.Product, product_id)
    if not product: raise HTTPException(404, "Product not found")
    return db.query(models.PurchasePriceHistory).filter(models.PurchasePriceHistory.product_id == product_id).order_by(models.PurchasePriceHistory.purchased_at.desc()).all()

@app.get("/inventory/valuation/advanced", tags=["Inventory Valuation"])
def advanced_inventory_valuation(db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    products = db.query(models.Product).filter(models.Product.active == True).all()
    rows=[]; total_cost=total_retail=0.0
    for p in products:
        qty=max(0,int(p.quantity or 0)); current=float(p.purchase_price or 0); retail=float(p.selling_price or 0)
        hist=db.query(models.PurchasePriceHistory).filter(models.PurchasePriceHistory.product_id==p.id).all()
        hist_qty=sum(int(x.quantity or 0) for x in hist); weighted=(sum(float(x.total_cost or 0) for x in hist)/hist_qty) if hist_qty else current
        cost=qty*weighted; rv=qty*retail; margin=rv-cost
        total_cost+=cost; total_retail+=rv
        rows.append({"product_id":p.id,"name":p.name,"barcode":p.barcode,"quantity":qty,"weighted_avg_cost":round(weighted,2),"current_purchase_price":current,"selling_price":retail,"cost_value":round(cost,2),"retail_value":round(rv,2),"potential_margin":round(margin,2),"margin_percent":round((margin/rv*100) if rv else 0,2)})
    dead=[r for r in rows if r["quantity"]>0 and r["cost_value"]>0 and r["potential_margin"]<0]
    return {"total_cost_value":round(total_cost,2),"total_retail_value":round(total_retail,2),"potential_gross_margin":round(total_retail-total_cost,2),"margin_percent":round(((total_retail-total_cost)/total_retail*100) if total_retail else 0,2),"weighted_average_unit_cost":round(total_cost/sum(r["quantity"] for r in rows),2) if sum(r["quantity"] for r in rows) else 0,"negative_margin_products":len(dead),"products":sorted(rows,key=lambda x:x["cost_value"],reverse=True)}

@app.get("/suppliers/performance/summary", tags=["Suppliers"])
def supplier_performance_summary(db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    rows=db.query(models.SupplierPerformance).all(); grouped={}
    for r in rows: grouped.setdefault(r.supplier_id,[]).append(r)
    out=[]
    for supplier_id,items in grouped.items():
        keys=["quality","delivery","price","service","compliance"]
        out.append({"supplier_id":supplier_id,"ratings_count":len(items),"overall":round(sum(float(x.overall or 0) for x in items)/len(items),2),**{k:round(sum(float(getattr(x,k) or 0) for x in items)/len(items),2) for k in keys},"latest_at":max(x.created_at for x in items)})
    return sorted(out,key=lambda x:x["overall"],reverse=True)

@app.get("/branches/{branch_id}/valuation", tags=["Branches"])
def branch_valuation(branch_id: int, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    branch=db.get(models.Branch,branch_id)
    if not branch or not branch.active: raise HTTPException(404,"Branch not found")
    rows=db.query(models.BranchStock).filter(models.BranchStock.branch_id==branch_id).join(models.Product).all()
    total=retail=0.0
    items=[]
    for r in rows:
        p=r.product; qty=int(r.quantity or 0); cost=qty*float(p.purchase_price or 0); rv=qty*float(p.selling_price or 0); total+=cost; retail+=rv
        items.append({"product_id":p.id,"product_name":p.name,"quantity":qty,"cost_value":round(cost,2),"retail_value":round(rv,2)})
    return {"branch_id":branch.id,"branch_name":branch.name,"cost_value":round(total,2),"retail_value":round(retail,2),"potential_margin":round(retail-total,2),"items":items}

# ---------------- Branches & Stock Transfers ----------------
TRANSFER_STATUSES = {"pending", "approved", "rejected", "completed"}

def _transfer_out(t):
    return {
        "id": t.id, "transfer_number": t.transfer_number,
        "from_branch_id": t.from_branch_id, "from_branch_name": t.from_branch.name,
        "to_branch_id": t.to_branch_id, "to_branch_name": t.to_branch.name,
        "status": t.status, "requested_by": t.requested_by, "approved_by": t.approved_by,
        "note": t.note, "created_at": t.created_at, "completed_at": t.completed_at,
        "items": [{"product_id": i.product_id, "quantity": i.quantity, "product_name": i.product.name if i.product else None} for i in t.items]
    }

@app.get("/branches", response_model=list[schemas.BranchOut], tags=["Branches"])
def list_branches(db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    return db.query(models.Branch).filter(models.Branch.active == True).order_by(models.Branch.name).all()

@app.post("/branches", response_model=schemas.BranchOut, tags=["Branches"])
def create_branch(data: schemas.BranchCreate, db: Session = Depends(get_db), user=Depends(require_admin)):
    code = data.code.strip().upper()
    if db.query(models.Branch).filter((models.Branch.code == code) | (models.Branch.name == data.name.strip())).first():
        raise HTTPException(409, "Branch name or code already exists")
    obj = models.Branch(name=data.name.strip(), code=code, address=data.address)
    db.add(obj); db.commit(); db.refresh(obj); return obj

@app.get("/branches/{branch_id}/stock", tags=["Branches"])
def branch_stock(branch_id: int, product_id: int | None = None, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    branch = db.get(models.Branch, branch_id)
    if not branch or not branch.active: raise HTTPException(404, "Branch not found")
    q = db.query(models.BranchStock).filter(models.BranchStock.branch_id == branch_id)
    if product_id is not None: q = q.filter(models.BranchStock.product_id == product_id)
    return [{"product_id": r.product_id, "product_name": r.product.name if r.product else None, "quantity": r.quantity, "updated_at": r.updated_at} for r in q.join(models.Product).order_by(models.Product.name).all()]

@app.get("/stock-transfers", response_model=list[schemas.StockTransferOut], tags=["Stock Transfers"])
def list_stock_transfers(status: str | None = None, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    q = db.query(models.StockTransfer)
    if status:
        if status not in TRANSFER_STATUSES: raise HTTPException(400, "Invalid transfer status")
        q = q.filter(models.StockTransfer.status == status)
    return [_transfer_out(t) for t in q.order_by(models.StockTransfer.created_at.desc()).all()]

@app.post("/stock-transfers", response_model=schemas.StockTransferOut, tags=["Stock Transfers"])
def create_stock_transfer(data: schemas.StockTransferCreate, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    if data.from_branch_id == data.to_branch_id: raise HTTPException(400, "Source and destination branches must be different")
    source = db.get(models.Branch, data.from_branch_id); target = db.get(models.Branch, data.to_branch_id)
    if not source or not source.active or not target or not target.active: raise HTTPException(404, "Branch not found")
    seen = set()
    for item in data.items:
        if item.product_id in seen: raise HTTPException(400, "Duplicate product in transfer")
        seen.add(item.product_id)
        product = db.get(models.Product, item.product_id)
        if not product or not product.active: raise HTTPException(404, f"Product {item.product_id} not found")
        row = db.query(models.BranchStock).filter_by(branch_id=source.id, product_id=product.id).first()
        available = row.quantity if row else (product.quantity if source.code == "MAIN" else 0)
        if available < item.quantity: raise HTTPException(409, f"Insufficient stock for {product.name}; available: {available}")
    t = models.StockTransfer(transfer_number="TRF-" + uuid4().hex[:10].upper(), from_branch_id=source.id, to_branch_id=target.id, status="pending", requested_by=user.id, note=data.note)
    db.add(t); db.flush()
    for item in data.items: db.add(models.StockTransferItem(transfer_id=t.id, product_id=item.product_id, quantity=item.quantity))
    db.commit(); db.refresh(t); return _transfer_out(t)

@app.patch("/stock-transfers/{transfer_id}/approve", response_model=schemas.StockTransferOut, tags=["Stock Transfers"])
def approve_stock_transfer(transfer_id: int, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    t = db.query(models.StockTransfer).filter_by(id=transfer_id).with_for_update().first()
    if not t: raise HTTPException(404, "Transfer not found")
    if t.status != "pending": raise HTTPException(409, "Only pending transfers can be approved")
    if t.from_branch_id == t.to_branch_id: raise HTTPException(400, "Invalid branches")
    # Claim the pending transfer atomically. The conditional UPDATE is respected by SQLite and PostgreSQL;
    # a concurrent approver will see rowcount 0 and cannot apply the stock movement twice.
    claim = db.query(models.StockTransfer).filter_by(id=transfer_id, status="pending").update(
        {"status": "completed", "approved_by": user.id, "completed_at": datetime.utcnow()},
        synchronize_session=False
    )
    if claim != 1:
        db.rollback()
        raise HTTPException(409, "Transfer was already processed by another request")
    db.flush()
    for item in t.items:
        source_row = db.query(models.BranchStock).filter_by(branch_id=t.from_branch_id, product_id=item.product_id).with_for_update().first()
        product = db.query(models.Product).filter_by(id=item.product_id).with_for_update().first()
        if not product: raise HTTPException(404, "Product not found")
        if not source_row:
            available = product.quantity if t.from_branch.code == "MAIN" else 0
            source_row = models.BranchStock(branch_id=t.from_branch_id, product_id=item.product_id, quantity=available); db.add(source_row); db.flush()
        if source_row.quantity < item.quantity: raise HTTPException(409, f"Insufficient stock for {product.name}")
    for item in t.items:
        source_row = db.query(models.BranchStock).filter_by(branch_id=t.from_branch_id, product_id=item.product_id).with_for_update().first()
        target_row = db.query(models.BranchStock).filter_by(branch_id=t.to_branch_id, product_id=item.product_id).with_for_update().first()
        if not target_row:
            target_row = models.BranchStock(branch_id=t.to_branch_id, product_id=item.product_id, quantity=0); db.add(target_row)
        source_row.quantity -= item.quantity; target_row.quantity += item.quantity
        if t.from_branch.code == "MAIN": db.get(models.Product, item.product_id).quantity -= item.quantity
        if t.to_branch.code == "MAIN": db.get(models.Product, item.product_id).quantity += item.quantity
        db.add(models.StockMovement(product_id=item.product_id, movement_type="out", quantity=item.quantity, note=f"Transfer {t.transfer_number} to {t.to_branch.name}", user_id=user.id))
        db.add(models.StockMovement(product_id=item.product_id, movement_type="in", quantity=item.quantity, note=f"Transfer {t.transfer_number} from {t.from_branch.name}", user_id=user.id))
    db.commit(); db.refresh(t); return _transfer_out(t)

@app.patch("/stock-transfers/{transfer_id}/reject", response_model=schemas.StockTransferOut, tags=["Stock Transfers"])
def reject_stock_transfer(transfer_id: int, db: Session = Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    t = db.get(models.StockTransfer, transfer_id)
    if not t: raise HTTPException(404, "Transfer not found")
    if t.status != "pending": raise HTTPException(409, "Only pending transfers can be rejected")
    t.status = "rejected"; t.approved_by = user.id; db.commit(); db.refresh(t); return _transfer_out(t)

@app.get("/suppliers/{supplier_id}/performance", response_model=list[schemas.SupplierPerformanceOut], tags=["Suppliers"])
def supplier_performance(supplier_id: str, db: Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist"))):
    return db.query(models.SupplierPerformance).filter(models.SupplierPerformance.supplier_id==supplier_id).order_by(models.SupplierPerformance.created_at.desc()).all()

@app.post("/suppliers/{supplier_id}/performance", response_model=schemas.SupplierPerformanceOut, tags=["Suppliers"])
def rate_supplier(supplier_id: str, data: schemas.SupplierPerformanceCreate, db: Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist"))):
    overall = round((data.quality + data.delivery + data.price + data.service + data.compliance) / 5, 2)
    obj=models.SupplierPerformance(supplier_id=supplier_id, quality=data.quality, delivery=data.delivery, price=data.price, service=data.service, compliance=data.compliance, overall=overall, notes=data.notes, rated_by=user.id)
    db.add(obj); db.commit(); db.refresh(obj); return obj

@app.get("/reports/summary",tags=["Reports"])
def summary(db:Session=Depends(get_db),user=Depends(require_roles("admin", "pharmacist"))):
    today=date.today(); start=today-timedelta(days=29)
    # Revenue is transaction-date based: sales during the period minus refunds issued during the period.
    sales=db.query(models.Sale).filter(func.date(models.Sale.created_at)>=start.isoformat(), func.date(models.Sale.created_at)<=today.isoformat()).all()
    active_sales=[sale for sale in sales if sale.status not in {"cancelled", "returned"}]
    returned_total=(db.query(func.coalesce(func.sum(models.SaleReturn.total_amount),0))
        .join(models.Sale, models.Sale.id == models.SaleReturn.sale_id)
        .filter(func.date(models.SaleReturn.created_at)>=start.isoformat(),
                func.date(models.SaleReturn.created_at)<=today.isoformat(),
                models.SaleReturn.kind == "return",
                models.Sale.status != "cancelled").scalar() or 0)
    products=db.query(models.Product).filter(models.Product.active==True).all()
    gross_sales=sum(float(s.total or 0) for s in sales if s.status != "cancelled")
    return {"period_start":start.isoformat(),"period_end":today.isoformat(),"sales_count":len(active_sales),"revenue":round(max(0, gross_sales-float(returned_total)),2),"low_stock_count":sum(p.quantity<=p.reorder_level for p in products),"expired_count":sum(bool(p.expiry_date and p.expiry_date<today) for p in products),"expiring_within_30_days":sum(bool(p.expiry_date and today<=p.expiry_date<=today+timedelta(days=30)) for p in products)}
@app.get("/reports/low-stock",tags=["Reports"])
def low_stock(db:Session=Depends(get_db),user=Depends(require_roles("admin", "pharmacist"))): return db.query(models.Product).filter(models.Product.active==True,models.Product.quantity<=models.Product.reorder_level).order_by(models.Product.quantity).all()
@app.get("/reports/expiry",tags=["Reports"])
def expiry(days:int=Query(30,ge=0,le=365),db:Session=Depends(get_db),user=Depends(require_roles("admin", "pharmacist"))):
    end=date.today()+timedelta(days=days); return db.query(models.Product).filter(models.Product.active==True,models.Product.expiry_date!=None,models.Product.expiry_date<=end).order_by(models.Product.expiry_date).all()

# Generic persistence layer for the remaining frontend modules. The UI keeps its local cache for instant UX,
# while every mutation is persisted server-side and restored on next login.
def _sync_user(user): return user
@app.get("/sync/{module}",tags=["Sync"])
def sync_list(module:str,db:Session=Depends(get_db),user=Depends(current_user)):
    require_sync_access(module, user)
    q=db.query(models.SyncRecord).filter(models.SyncRecord.module==module)
    # New records are user-scoped. Legacy rows without an owner are visible only to
    # administrators for controlled review/migration, never to every module reader.
    if str(getattr(user, "role", "")).strip().lower() == "admin":
        q=q.filter((models.SyncRecord.user_id==user.id) | (models.SyncRecord.user_id==None))
    else:
        q=q.filter(models.SyncRecord.user_id==user.id)
    return [r.payload for r in q.order_by(models.SyncRecord.updated_at.desc()).all()]
@app.put("/sync/{module}/{record_id}",tags=["Sync"])
def sync_upsert(module:str,record_id:str,payload:dict,db:Session=Depends(get_db),user=Depends(current_user)):
    require_sync_access(module, user)
    storage_id = f"u{user.id}:{module}:{record_id}"
    rec=db.query(models.SyncRecord).filter_by(module=module,record_id=storage_id,user_id=user.id).first()
    if rec: rec.payload=payload
    else: db.add(models.SyncRecord(module=module,record_id=storage_id,payload=payload,user_id=user.id))
    db.commit(); return payload
@app.delete("/sync/{module}/{record_id}",tags=["Sync"])
def sync_delete(module:str,record_id:str,db:Session=Depends(get_db),user=Depends(current_user)):
    require_sync_access(module, user)
    storage_id = f"u{user.id}:{module}:{record_id}"
    rec=db.query(models.SyncRecord).filter_by(module=module,record_id=storage_id,user_id=user.id).first()
    if rec: db.delete(rec); db.commit()
    return {"ok":True}


# ============================================================
# Enterprise / Commercial Readiness APIs
# ============================================================
try:
    from sqlalchemy import or_, and_
    from . import enterprise_models
except ImportError:
    enterprise_models = None

ENTERPRISE_FEATURES = {
    "drug_knowledge": True,
    "smart_search": True,
    "smart_procurement": True,
    "advanced_alerts": True,
    "whatsapp_invoice_share": True,
    "data_migrations": True,
    "advanced_permissions": True,
    "cash_audit": True,
    "invoice_audit": True,
    "product_timeline": True,
    "feature_flags": True,
    "saas_ready": True,
    "subscriptions_ready": True,
    "accessibility": True,
    "performance": True,
    "idempotency": True,
    "integrity_checks": True,
}

def _audit(db, user, action, entity_type=None, entity_id=None, before=None, after=None, reason=None):
    if enterprise_models is None: return
    db.add(enterprise_models.AuditEvent(user_id=getattr(user, "id", None), action=action,
        entity_type=entity_type, entity_id=str(entity_id) if entity_id is not None else None,
        before_data=before or {}, after_data=after or {}, reason=reason))

def _seed_enterprise(db):
    if enterprise_models is None: return
    for key, enabled in ENTERPRISE_FEATURES.items():
        if not db.query(enterprise_models.FeatureFlag).filter_by(key=key).first():
            db.add(enterprise_models.FeatureFlag(key=key, enabled=enabled))
    if not db.query(enterprise_models.SubscriptionPlan).count():
        db.add_all([
            enterprise_models.SubscriptionPlan(code="starter", name="Starter", monthly_price=0, limits={"branches":1,"users":3}),
            enterprise_models.SubscriptionPlan(code="professional", name="Professional", monthly_price=0, limits={"branches":5,"users":20}),
            enterprise_models.SubscriptionPlan(code="enterprise", name="Enterprise", monthly_price=0, limits={"branches":999,"users":999}),
        ])
    if not db.query(enterprise_models.DataMigration).filter_by(version="enterprise-v1").first():
        db.add(enterprise_models.DataMigration(version="enterprise-v1", status="completed", details={"created":"drug_information,feature_flags,data_migrations,audit_events,idempotency_records,saas_tables"}))
    db.commit()

_seed_db = next(get_db())
try:
    _seed_enterprise(_seed_db)
except Exception:
    logger.exception("Enterprise seed failed during startup; application startup cannot guarantee enterprise schema readiness")
    raise
finally:
    _seed_db.close()

@app.get("/enterprise/features", tags=["Enterprise"])
def enterprise_features(db:Session=Depends(get_db), user=Depends(current_user)):
    rows=db.query(enterprise_models.FeatureFlag).order_by(enterprise_models.FeatureFlag.key).all()
    return {"features": {r.key:r.enabled for r in rows}, "capabilities": ENTERPRISE_FEATURES}

@app.patch("/enterprise/features/{key}", tags=["Enterprise"])
def set_enterprise_feature(key:str, data:dict, db:Session=Depends(get_db), user=Depends(require_admin)):
    if key not in ENTERPRISE_FEATURES: raise HTTPException(404,"Unknown feature")
    row=db.query(enterprise_models.FeatureFlag).filter_by(key=key).first()
    if not row: row=enterprise_models.FeatureFlag(key=key, enabled=True); db.add(row)
    row.enabled=bool(data.get("enabled", row.enabled)); row.config=data.get("config", row.config or {})
    _audit(db,user,"feature.toggle","feature",key,after={"enabled":row.enabled})
    db.commit(); return {"key":key,"enabled":row.enabled,"config":row.config}

@app.get("/drug-knowledge/search", tags=["Drug Knowledge"])
def drug_knowledge_search(q:str|None=None, db:Session=Depends(get_db), user=Depends(current_user)):
    q=(q or "").strip()
    if not q: return {"items":[],"query":""}
    like=f"%{q}%"
    rows=(db.query(enterprise_models.DrugInfo, models.Product)
        .join(models.Product, models.Product.id==enterprise_models.DrugInfo.product_id)
        .filter(models.Product.active==True)
        .filter(or_(models.Product.name.ilike(like), models.Product.barcode.ilike(like),
                    enterprise_models.DrugInfo.generic_name.ilike(like), enterprise_models.DrugInfo.active_ingredient.ilike(like),
                    enterprise_models.DrugInfo.concentration.ilike(like), enterprise_models.DrugInfo.dosage_form.ilike(like)))
        .order_by(models.Product.name).limit(100).all())
    return {"query":q,"items":[{"product_id":p.id,"name":p.name,"barcode":p.barcode,"generic_name":d.generic_name,
      "active_ingredient":d.active_ingredient,"concentration":d.concentration,"dosage_form":d.dosage_form,
      "manufacturer":d.manufacturer or p.manufacturer,"verified":d.verified} for d,p in rows]}

@app.put("/products/{product_id}/drug-info", tags=["Drug Knowledge"])
def upsert_drug_info(product_id:int, data:dict, db:Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist"))):
    product=db.get(models.Product,product_id)
    if not product: raise HTTPException(404,"Product not found")
    row=db.query(enterprise_models.DrugInfo).filter_by(product_id=product_id).first()
    if not row: row=enterprise_models.DrugInfo(product_id=product_id); db.add(row)
    allowed=["generic_name","active_ingredient","concentration","dosage_form","route","manufacturer","indications","warnings","storage_conditions","source","verified"]
    for k in allowed:
        if k in data: setattr(row,k,data[k])
    _audit(db,user,"drug-info.update","product",product_id,after={k:getattr(row,k) for k in allowed})
    db.commit(); db.refresh(row)
    return {k:getattr(row,k) for k in ["id","product_id"]+allowed}

@app.get("/products/{product_id}/timeline", tags=["Audit"])
def product_timeline(product_id:int, db:Session=Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    product=db.get(models.Product,product_id)
    if not product: raise HTTPException(404,"Product not found")
    events=[]
    for m in db.query(models.StockMovement).filter_by(product_id=product_id).order_by(models.StockMovement.created_at.desc()).limit(500):
        events.append({"type":"stock","action":m.movement_type,"quantity":m.quantity,"note":m.note,"at":m.created_at})
    if enterprise_models:
        for a in db.query(enterprise_models.AuditEvent).filter_by(entity_type="product",entity_id=str(product_id)).order_by(enterprise_models.AuditEvent.created_at.desc()).limit(500):
            events.append({"type":"audit","action":a.action,"reason":a.reason,"before":a.before_data,"after":a.after_data,"at":a.created_at})
    for h in db.query(models.PurchasePriceHistory).filter_by(product_id=product_id).order_by(models.PurchasePriceHistory.purchased_at.desc()).limit(200):
        events.append({"type":"purchase_price","action":"purchase","supplier":h.supplier_name,"unit_price":h.unit_price,"quantity":h.quantity,"at":h.purchased_at})
    events.sort(key=lambda x:x.get("at") or datetime.min, reverse=True)
    return {"product_id":product_id,"product":product.name,"events":events[:800]}

@app.get("/inventory/procurement-recommendations", tags=["Smart Procurement"])
def procurement_recommendations(db:Session=Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    rows=[]
    today=datetime.utcnow().date()
    for p in db.query(models.Product).filter(models.Product.active==True).all():
        sales_30=(db.query(func.coalesce(func.sum(models.SaleItem.quantity-models.SaleItem.returned_quantity),0)).join(models.Sale, models.Sale.id==models.SaleItem.sale_id)
                  .filter(models.SaleItem.product_id==p.id, models.Sale.status != "cancelled", models.Sale.created_at >= datetime.utcnow()-__import__('datetime').timedelta(days=30))).scalar() or 0
        daily=float(sales_30)/30.0
        days_cover=(float(p.quantity)/daily) if daily>0 else 999
        if p.quantity <= p.reorder_level or days_cover < 14:
            target=max(p.reorder_level*2, int(round(daily*30)))
            qty=max(0,target-p.quantity)
            rows.append({"product_id":p.id,"name":p.name,"stock":p.quantity,"reorder_level":p.reorder_level,
              "sales_30d":int(sales_30),"daily_demand":round(daily,2),"days_of_cover":round(days_cover,1),"recommended_qty":qty,
              "priority":"critical" if p.quantity<=0 else ("high" if days_cover<7 else "medium")})
    return {"items":sorted(rows,key=lambda x:(0 if x["priority"]=="critical" else 1 if x["priority"]=="high" else 2,x["days_of_cover"]))}

@app.get("/alerts/advanced", tags=["Alerts"])
def advanced_alerts(db:Session=Depends(get_db), user=Depends(require_roles("admin", "pharmacist"))):
    today=datetime.utcnow().date(); alerts=[]
    for p in db.query(models.Product).filter(models.Product.active==True).all():
        if p.quantity<=0: alerts.append({"type":"stockout","severity":"critical","product_id":p.id,"message":f"{p.name}: نفد المخزون"})
        elif p.quantity<=p.reorder_level: alerts.append({"type":"low_stock","severity":"high","product_id":p.id,"message":f"{p.name}: المخزون منخفض"})
        if p.expiry_date:
            days=(p.expiry_date-today).days
            if days<0: alerts.append({"type":"expired","severity":"critical","product_id":p.id,"message":f"{p.name}: منتهي الصلاحية"})
            elif days<=30: alerts.append({"type":"expiry","severity":"high","product_id":p.id,"days":days,"message":f"{p.name}: الصلاحية خلال {days} يوم"})
    recent=db.query(models.Sale).filter(models.Sale.created_at>=datetime.utcnow()-__import__('datetime').timedelta(hours=24), models.Sale.status != "cancelled").count()
    if recent==0: alerts.append({"type":"sales","severity":"medium","message":"لا توجد مبيعات خلال آخر 24 ساعة"})
    return {"count":len(alerts),"items":alerts}

@app.get("/inventory/integrity-check", tags=["Integrity"])
def inventory_integrity_check(db:Session=Depends(get_db), user=Depends(require_roles("admin","pharmacist"))):
    issues=[]
    for p in db.query(models.Product).filter(models.Product.active==True).all():
        if p.quantity<0: issues.append({"type":"negative_stock","product_id":p.id,"quantity":p.quantity})
        if p.purchase_price<0 or p.selling_price<0: issues.append({"type":"negative_price","product_id":p.id})
        if p.selling_price and p.purchase_price and p.selling_price < p.purchase_price: issues.append({"type":"negative_margin","product_id":p.id,"purchase":p.purchase_price,"sale":p.selling_price})
    return {"ok":not issues,"issues":issues,"checked_at":datetime.utcnow().isoformat()}

@app.get("/audit/security-events", tags=["Audit"])
def security_events(limit: int = Query(100, ge=1, le=100), db: Session = Depends(get_db), user=Depends(require_admin)):
    rows = db.query(models.SecurityEvent).order_by(models.SecurityEvent.created_at.desc()).limit(limit).all()
    return [{"id": r.id, "type": r.type, "severity": r.severity, "message": r.message,
             "user_id": r.user_id, "metadata": r.event_metadata, "created_at": r.created_at} for r in rows]


@app.get("/audit/cash-register", tags=["Audit"])
def cash_register_audit(db:Session=Depends(get_db), user=Depends(require_admin)):
    # Unified cashier/shifts/sales audit from the current domain model.
    sales=db.query(models.Sale).order_by(models.Sale.created_at.desc()).limit(500).all()
    return {"sales":[{"id":s.id,"invoice_number":s.invoice_number,"total":s.total,"status":s.status,"returned_total":round(sum(r.total_amount for r in s.returns),2),"payment_method":s.payment_method,"user_id":s.user_id,"created_at":s.created_at} for s in sales]}

@app.get("/audit/invoices", tags=["Audit"])
def invoice_audit(db:Session=Depends(get_db), user=Depends(require_admin)):
    rows=[]
    for s in db.query(models.Sale).order_by(models.Sale.created_at.desc()).limit(1000):
        rows.append({"id":s.id,"invoice_number":s.invoice_number,"total":s.total,"status":s.status,"returned_quantity":sum(i.returned_quantity for i in s.items),"items_quantity":sum(i.quantity for i in s.items),"returns":[{"return_number":r.return_number,"kind":r.kind,"total_amount":r.total_amount,"reason":r.reason,"created_at":r.created_at} for r in s.returns],"user_id":s.user_id,"created_at":s.created_at,"client_reference":s.client_reference})
    return {"items":rows}

@app.get("/data-migrations", tags=["Migrations"])
def migration_status(db:Session=Depends(get_db), user=Depends(require_admin)):
    rows=db.query(enterprise_models.DataMigration).order_by(enterprise_models.DataMigration.id).all()
    return {"current":"enterprise-v1","migrations":[{"version":r.version,"status":r.status,"applied_at":r.applied_at,"details":r.details} for r in rows]}

@app.post("/data-migrations/backup-manifest", tags=["Migrations"])
def backup_manifest(db:Session=Depends(get_db), user=Depends(require_admin)):
    tables=["users","products","sales","sale_items","stock_movements","purchase_price_history","supplier_performance","branches","branch_stock","stock_transfers","drug_information","audit_events"]
    return {"version":"enterprise-v1","generated_at":datetime.utcnow().isoformat(),"tables":tables,"policy":"forward-only, backup-before-upgrade"}

@app.get("/saas/capabilities", tags=["SaaS"])
def saas_capabilities(db:Session=Depends(get_db), user=Depends(require_admin)):
    plans=db.query(enterprise_models.SubscriptionPlan).all()
    tenants=db.query(enterprise_models.PharmacyTenant).count()
    return {"multi_tenant_ready":True,"tenants":tenants,"plans":[{"code":p.code,"name":p.name,"monthly_price":p.monthly_price,"limits":p.limits} for p in plans],"billing_provider":None}

@app.get("/performance/health", tags=["System"])
def performance_health(db:Session=Depends(get_db), user=Depends(current_user)):
    counts={"products":db.query(models.Product).count(),"sales":db.query(models.Sale).count(),"branches":db.query(models.Branch).count()}
    return {"status":"ok","counts":counts,"pagination":"supported","recommendation":"use paginated API endpoints for large datasets"}
