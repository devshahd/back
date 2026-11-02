import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Always load the project-local .env, regardless of the current working directory.
ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(ENV_FILE)
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase

logger = logging.getLogger("pharmasys.database")

DEFAULT_DB_PATH = (Path(__file__).resolve().parents[2] / "pharmacy.db").as_posix()
_raw_database_url = os.getenv("DATABASE_URL", "").strip()

def _normalize_database_url(value: str) -> str:
    if not value:
        return f"sqlite:///{DEFAULT_DB_PATH}"
    # Resolve relative SQLite paths against backend/, not the caller's working directory.
    if value.startswith("sqlite:///") and not value.startswith("sqlite:////"):
        raw_path = value[len("sqlite:///"): ]
        if raw_path and not Path(raw_path).is_absolute():
            resolved = (ENV_FILE.parent / raw_path).resolve()
            return "sqlite:///" + resolved.as_posix()
    return value

DATABASE_URL = _normalize_database_url(_raw_database_url)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def ensure_compat_schema():
    """Small forward-only compatibility migration for databases created by v2.0.
    New deployments can use Alembic later; this keeps existing SQLite/Postgres installs bootable.
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        if "sales" in tables:
            cols = {c["name"] for c in inspector.get_columns("sales")}
            if "client_reference" not in cols:
                conn.execute(text("ALTER TABLE sales ADD COLUMN client_reference VARCHAR(160)"))
                try: conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_sales_client_reference ON sales (client_reference)"))
                except Exception: pass
        if "sales" in tables:
            cols = {c["name"] for c in inspector.get_columns("sales")}
            if "status" not in cols:
                conn.execute(text("ALTER TABLE sales ADD COLUMN status VARCHAR(30) DEFAULT 'completed'"))
            try: conn.execute(text("CREATE INDEX IF NOT EXISTS ix_sales_status ON sales (status)"))
            except Exception: pass
        if "sales" in tables:
            cols = {c["name"] for c in inspector.get_columns("sales")}
            if "request_hash" not in cols:
                conn.execute(text("ALTER TABLE sales ADD COLUMN request_hash VARCHAR(64) DEFAULT ''"))
            if "branch_id" not in cols:
                conn.execute(text("ALTER TABLE sales ADD COLUMN branch_id INTEGER REFERENCES branches(id)"))
            try: conn.execute(text("CREATE INDEX IF NOT EXISTS ix_sales_branch_id ON sales (branch_id)"))
            except Exception: pass
        if "products" in tables:
            cols = {c["name"] for c in inspector.get_columns("products")}
            if "archived_barcode" not in cols:
                conn.execute(text("ALTER TABLE products ADD COLUMN archived_barcode VARCHAR(80)"))
            try: conn.execute(text("CREATE INDEX IF NOT EXISTS ix_products_archived_barcode ON products (archived_barcode)"))
            except Exception: pass
        if "delivery_orders" in tables:
            cols = {c["name"] for c in inspector.get_columns("delivery_orders")}
            if "sale_id" not in cols:
                conn.execute(text("ALTER TABLE delivery_orders ADD COLUMN sale_id INTEGER REFERENCES sales(id)"))
            try: conn.execute(text("CREATE INDEX IF NOT EXISTS ix_delivery_orders_sale_id ON delivery_orders (sale_id)"))
            except Exception: pass
            if "active_sale_id" not in cols:
                conn.execute(text("ALTER TABLE delivery_orders ADD COLUMN active_sale_id INTEGER REFERENCES sales(id)"))
            try: conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_delivery_orders_active_sale_id ON delivery_orders (active_sale_id)"))
            except Exception:
                # Existing duplicate legacy rows are handled by the API duplicate check; do not prevent startup.
                pass
        if "sale_items" in tables:
            cols = {c["name"] for c in inspector.get_columns("sale_items")}
            if "returned_quantity" not in cols:
                conn.execute(text("ALTER TABLE sale_items ADD COLUMN returned_quantity INTEGER DEFAULT 0"))
        if "sale_returns" in tables:
            cols = {c["name"] for c in inspector.get_columns("sale_returns")}
            if "request_hash" not in cols:
                conn.execute(text("ALTER TABLE sale_returns ADD COLUMN request_hash VARCHAR(64) DEFAULT ''"))
        if "purchase_price_history" in tables:
            cols = {c["name"] for c in inspector.get_columns("purchase_price_history")}
            additions = {
                "supplier_name": "VARCHAR(180)",
                "purchase_number": "VARCHAR(60)",
                "unit_price": "FLOAT DEFAULT 0",
                "quantity": "INTEGER DEFAULT 0",
                "total_cost": "FLOAT DEFAULT 0",
                "purchased_at": "TIMESTAMP",
            }
            for name, ddl in additions.items():
                if name not in cols:
                    conn.execute(text(f"ALTER TABLE purchase_price_history ADD COLUMN {name} {ddl}"))
            try: conn.execute(text("CREATE INDEX IF NOT EXISTS ix_purchase_price_history_purchase_number ON purchase_price_history (purchase_number)"))
            except Exception: pass
        if "sync_records" in tables:
            cols = {c["name"] for c in inspector.get_columns("sync_records")}
            if "user_id" not in cols:
                conn.execute(text("ALTER TABLE sync_records ADD COLUMN user_id INTEGER"))
                try: conn.execute(text("CREATE INDEX IF NOT EXISTS ix_sync_records_user_id ON sync_records (user_id)"))
                except Exception: pass

        if "users" in tables:
            cols = {c["name"] for c in inspector.get_columns("users")}
            additions = {
                "failed_attempts": "INTEGER DEFAULT 0",
                "locked_until": "TIMESTAMP",
                "last_failed_login": "TIMESTAMP",
                "last_login_at": "TIMESTAMP",
                "password_changed_at": "TIMESTAMP",
            }
            for name, ddl in additions.items():
                if name not in cols:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))

        # Enforce case-insensitive category uniqueness at the database level.
        # Do not delete/merge legacy categories automatically because products may reference them.
        if "categories" in tables:
            duplicate_groups = conn.execute(text("""
                SELECT lower(trim(name)) AS normalized_name, COUNT(*) AS row_count
                FROM categories
                GROUP BY lower(trim(name))
                HAVING COUNT(*) > 1
                LIMIT 10
            """)).fetchall()
            if duplicate_groups:
                logger.error(
                    "Cannot create case-insensitive category unique index: legacy duplicates exist (%s). "
                    "Resolve these category names and restart PharmaSys.",
                    [(row[0], row[1]) for row in duplicate_groups],
                )
            else:
                try:
                    conn.execute(text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS uq_categories_name_lower "
                        "ON categories (lower(trim(name)))"
                    ))
                except Exception:
                    logger.exception("Could not create case-insensitive unique index for categories")

        # Keep an explicit, inspectable schema version ledger. The compatibility
        # migration above remains idempotent so existing v2 installations can be
        # upgraded in place after taking a backup.
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(100) PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details VARCHAR(500)
            )
        """))
        migration_version = "2026-10-26-critical-sales-delivery-v4"
        already_applied = conn.execute(
            text("SELECT version FROM schema_migrations WHERE version = :version"),
            {"version": migration_version}
        ).first()
        if not already_applied:
            conn.execute(
                text("INSERT INTO schema_migrations (version, details) VALUES (:version, :details)"),
                {"version": migration_version, "details": "Idempotent v2 compatibility columns and indexes"}
            )
