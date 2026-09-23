import base64
import hashlib
import hmac
import io
import secrets
import sqlite3
import uuid
from datetime import datetime, date
from urllib.parse import urlparse

import pandas as pd
import pyotp
import qrcode
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image, ImageDraw, ImageFont

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="AirNexus Secure Identity Verification",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_FILE = "event_identity.db"

# ============================================================
# SECRETS / SECURITY CONFIG
# ============================================================
def get_secret(name, default=""):
    try:
        value = st.secrets.get(name, default)
        return str(value) if value is not None else default
    except Exception:
        return default

APP_BASE_URL = get_secret("APP_BASE_URL", "").strip().rstrip("/")

# Administrator password: full record management
ADMIN_PASSWORD = get_secret("ADMIN_PASSWORD", "admin123")

# Scanner password: only authorized guards/staff can open QR verification pages
SCANNER_PASSWORD = get_secret("SCANNER_PASSWORD", "scanner123")

# Optional MFA for admin login
ADMIN_TOTP_SECRET = get_secret("ADMIN_TOTP_SECRET", "").strip()

# Optional dedicated encryption key
APP_ENCRYPTION_KEY = get_secret("APP_ENCRYPTION_KEY", "").strip()

# Optional master secret for deriving encryption/live-code keys
APP_MASTER_SECRET = get_secret("APP_MASTER_SECRET", "").strip()

# Optional dedicated live-code secret
LIVE_SECURITY_SECRET = get_secret("LIVE_SECURITY_SECRET", "").strip()

def secure_equal(a, b):
    return hmac.compare_digest(str(a), str(b))

def derive_fallback_secret():
    """
    Provides a stable fallback key without showing an encryption warning.
    In production, APP_MASTER_SECRET or APP_ENCRYPTION_KEY is still recommended.
    """
    base = APP_MASTER_SECRET or f"{ADMIN_PASSWORD}|{SCANNER_PASSWORD}|airnexus-secure-app"
    return hashlib.sha256(base.encode("utf-8")).digest()

def get_fernet():
    if APP_ENCRYPTION_KEY:
        try:
            return Fernet(APP_ENCRYPTION_KEY.encode("utf-8"))
        except Exception:
            st.error("APP_ENCRYPTION_KEY in Streamlit Secrets is invalid.")
            st.stop()

    # Stable fallback derived from configured secrets.
    key = base64.urlsafe_b64encode(derive_fallback_secret())
    return Fernet(key)

FERNET = get_fernet()

def get_live_secret_bytes():
    if LIVE_SECURITY_SECRET:
        return LIVE_SECURITY_SECRET.encode("utf-8")
    return hashlib.sha256(derive_fallback_secret() + b":live-code").digest()

LIVE_SECRET = get_live_secret_bytes()

# ============================================================
# DATABASE
# ============================================================
def get_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def table_columns(conn, table_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}

def ensure_column(conn, table_name, column_name, definition):
    if column_name not in table_columns(conn, table_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")

def init_db():
    conn = get_connection()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS members (
            id TEXT PRIMARY KEY,
            card_id TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            category TEXT NOT NULL,
            position TEXT NOT NULL,
            department TEXT,
            organization TEXT,
            email TEXT,
            phone TEXT,
            emergency_contact TEXT,
            blood_group TEXT,
            status TEXT NOT NULL DEFAULT 'Active',
            notes TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    ensure_column(conn, "members", "photo", "BLOB")
    ensure_column(conn, "members", "qr_token_hash", "TEXT")
    ensure_column(conn, "members", "qr_token_enc", "TEXT")
    ensure_column(conn, "members", "expiry_date", "TEXT")
    ensure_column(conn, "members", "issue_version", "INTEGER DEFAULT 1")
    ensure_column(conn, "members", "last_reissued_at", "TEXT")
    ensure_column(conn, "members", "updated_at", "TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT,
            card_id TEXT,
            scan_time TEXT NOT NULL,
            verification_id TEXT NOT NULL,
            result TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            member_id TEXT,
            card_id TEXT,
            action_time TEXT NOT NULL,
            details TEXT
        )
        """
    )

    conn.commit()
    conn.close()

init_db()

# ============================================================
# TOKEN SECURITY
# ============================================================
def new_qr_token():
    return secrets.token_urlsafe(32)

def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def encrypt_token(token):
    return FERNET.encrypt(token.encode("utf-8")).decode("utf-8")

def decrypt_token(enc):
    if not enc:
        return None
    try:
        return FERNET.decrypt(enc.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        return None

def build_verification_url(token):
    if APP_BASE_URL:
        return f"{APP_BASE_URL}/?verify={token}"
    return f"http://localhost:8501/?verify={token}"

def make_qr_from_token(token):
    url = build_verification_url(token)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return image, url

def png_bytes(img):
    buff = io.BytesIO()
    img.save(buff, format="PNG")
    return buff.getvalue()

# ============================================================
# DB HELPERS
# ============================================================
def add_audit(action, member_id=None, card_id=None, details=""):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO admin_audit(action, member_id, card_id, action_time, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (action, member_id, card_id, datetime.now().isoformat(timespec="seconds"), details),
    )
    conn.commit()
    conn.close()

def add_member(data):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO members (
            id, card_id, full_name, category, position, department,
            organization, email, phone, emergency_contact, blood_group,
            status, notes, created_at, photo, qr_token_hash, qr_token_enc,
            expiry_date, issue_version, last_reissued_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["id"], data["card_id"], data["full_name"], data["category"],
            data["position"], data["department"], data["organization"],
            data["email"], data["phone"], data["emergency_contact"],
            data["blood_group"], data["status"], data["notes"],
            data["created_at"], data["photo"], data["qr_token_hash"],
            data["qr_token_enc"], data["expiry_date"], data["issue_version"],
            data["last_reissued_at"], data["updated_at"],
        ),
    )
    conn.commit()
    conn.close()
    add_audit("CREATE_MEMBER", data["id"], data["card_id"], "New identity created")

def update_member(member_id, data):
    conn = get_connection()
    conn.execute(
        """
        UPDATE members SET
            card_id=?, full_name=?, category=?, position=?, department=?,
            organization=?, email=?, phone=?, emergency_contact=?,
            blood_group=?, status=?, notes=?, expiry_date=?, updated_at=?
        WHERE id=?
        """,
        (
            data["card_id"], data["full_name"], data["category"],
            data["position"], data["department"], data["organization"],
            data["email"], data["phone"], data["emergency_contact"],
            data["blood_group"], data["status"], data["notes"],
            data["expiry_date"], datetime.now().isoformat(timespec="seconds"),
            member_id,
        ),
    )
    conn.commit()
    conn.close()
    add_audit("UPDATE_MEMBER", member_id, data["card_id"], "Identity record updated")

def update_photo(member_id, card_id, photo_bytes):
    conn = get_connection()
    conn.execute(
        "UPDATE members SET photo=?, updated_at=? WHERE id=?",
        (photo_bytes, datetime.now().isoformat(timespec="seconds"), member_id),
    )
    conn.commit()
    conn.close()
    add_audit("UPDATE_PHOTO", member_id, card_id, "Photo changed")

def delete_member(member_id, card_id):
    conn = get_connection()
    conn.execute("DELETE FROM members WHERE id=?", (member_id,))
    conn.commit()
    conn.close()
    add_audit("DELETE_MEMBER", member_id, card_id, "Identity deleted")

def get_all_members():
    conn = get_connection()
    df = pd.read_sql_query(
        """
        SELECT id, card_id, full_name, category, position, department,
               organization, email, phone, emergency_contact, blood_group,
               status, notes, created_at, expiry_date, issue_version,
               last_reissued_at, updated_at
        FROM members
        ORDER BY full_name
        """,
        conn,
    )
    conn.close()
    return df

def get_member_by_id(member_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM members WHERE id=?", (member_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_member_by_token(token):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM members WHERE qr_token_hash=?",
        (hash_token(token),),
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def reissue_qr(member_id, card_id):
    token = new_qr_token()
    conn = get_connection()
    row = conn.execute(
        "SELECT COALESCE(issue_version, 1) AS issue_version FROM members WHERE id=?",
        (member_id,),
    ).fetchone()
    next_version = int(row["issue_version"] or 1) + 1 if row else 2

    now = datetime.now().isoformat(timespec="seconds")
    conn.execute(
        """
        UPDATE members
        SET qr_token_hash=?, qr_token_enc=?, issue_version=?,
            last_reissued_at=?, updated_at=?
        WHERE id=?
        """,
        (hash_token(token), encrypt_token(token), next_version, now, now, member_id),
    )
    conn.commit()
    conn.close()
    add_audit("REISSUE_QR", member_id, card_id, f"QR rotated to version {next_version}")
    return token

def set_status(member_id, card_id, status):
    conn = get_connection()
    conn.execute(
        "UPDATE members SET status=?, updated_at=? WHERE id=?",
        (status, datetime.now().isoformat(timespec="seconds"), member_id),
    )
    conn.commit()
    conn.close()
    add_audit("STATUS_CHANGE", member_id, card_id, f"Status changed to {status}")

def log_scan(member, verification_id, result):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO scan_logs(member_id, card_id, scan_time, verification_id, result)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            member["id"] if member else None,
            member["card_id"] if member else None,
            datetime.now().isoformat(timespec="seconds"),
            verification_id,
            result,
        ),
    )
    conn.commit()
    conn.close()

def get_recent_scans(limit=500):
    conn = get_connection()
    df = pd.read_sql_query(
        """
        SELECT scan_time, card_id, verification_id, result
        FROM scan_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        conn,
        params=(limit,),
    )
    conn.close()
    return df

def get_audit_log(limit=500):
    conn = get_connection()
    df = pd.read_sql_query(
        """
        SELECT action_time, action, card_id, details
        FROM admin_audit
        ORDER BY id DESC
        LIMIT ?
        """,
        conn,
        params=(limit,),
    )
    conn.close()
    return df

# ============================================================
# HELPERS
# ============================================================
def safe_text(value):
    if value is None:
        return "-"
    value = str(value).strip()
    return value if value else "-"

def generate_card_id(category):
    prefix = {
        "Executive Council": "EC",
        "Organizer": "ORG",
        "Volunteer": "VOL",
    }.get(category, "ID")
    return f"AX-{prefix}-{secrets.token_hex(3).upper()}"

def photo_image(photo_bytes):
    if not photo_bytes:
        return None
    try:
        return Image.open(io.BytesIO(photo_bytes)).convert("RGB")
    except Exception:
        return None

def official_host():
    if not APP_BASE_URL:
        return "localhost / development"
    try:
        return urlparse(APP_BASE_URL).netloc or APP_BASE_URL
    except Exception:
        return APP_BASE_URL

def live_security_code(member_id):
    window = int(datetime.now().timestamp() // 30)
    msg = f"{member_id}:{window}".encode("utf-8")
    digest = hmac.new(LIVE_SECRET, msg, hashlib.sha256).hexdigest()
    return f"{int(digest[:12], 16) % 1000000:06d}"

def make_id_card(member, token):
    width, height = 1050, 650
    card = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(card)

    try:
        title_font = ImageFont.truetype("DejaVuSans-Bold.ttf", 46)
        name_font = ImageFont.truetype("DejaVuSans-Bold.ttf", 40)
        normal_font = ImageFont.truetype("DejaVuSans.ttf", 28)
        small_font = ImageFont.truetype("DejaVuSans.ttf", 22)
    except Exception:
        title_font = name_font = normal_font = small_font = ImageFont.load_default()

    draw.rectangle([0, 0, width, 110], fill=(18, 43, 84))
    draw.text((40, 30), "AIRNEXUS OFFICIAL IDENTITY CARD", fill="white", font=title_font)

    pimg = photo_image(member.get("photo"))
    if pimg:
        pimg.thumbnail((230, 260))
        px = 55 + (230 - pimg.width) // 2
        py = 160 + (260 - pimg.height) // 2
        card.paste(pimg, (px, py))
        draw.rectangle([55, 160, 285, 420], outline=(20, 20, 20), width=2)
    else:
        draw.rectangle([55, 160, 285, 420], outline=(60, 60, 60), width=2)
        draw.text((95, 275), "PHOTO", fill=(100, 100, 100), font=normal_font)

    draw.text((330, 165), member["full_name"], fill=(10, 10, 10), font=name_font)
    draw.text((330, 225), member["position"], fill=(25, 55, 100), font=normal_font)
    draw.text((330, 285), f"Category: {member['category']}", fill=(30, 30, 30), font=small_font)
    draw.text((330, 325), f"Committee: {member.get('department') or '-'}", fill=(30, 30, 30), font=small_font)
    draw.text((330, 365), f"Card ID: {member['card_id']}", fill=(30, 30, 30), font=small_font)
    draw.text((330, 405), f"Status: {member['status']}", fill=(30, 30, 30), font=small_font)

    qr_img, _ = make_qr_from_token(token)
    qr_img = qr_img.resize((230, 230))
    card.paste(qr_img, (785, 165))

    draw.text((770, 410), "SCAN FOR LIVE", fill=(20, 20, 20), font=small_font)
    draw.text((790, 445), "VERIFICATION", fill=(20, 20, 20), font=small_font)

    draw.rectangle([0, 540, width, 650], fill=(245, 247, 250))
    draw.text((40, 565), f"Official verification: {official_host()}", fill=(60, 60, 60), font=small_font)
    draw.text((40, 605), f"Issue Version: {member.get('issue_version') or 1}", fill=(60, 60, 60), font=small_font)

    return card

# ============================================================
# SESSION STATE
# ============================================================
if "admin_authenticated" not in st.session_state:
    st.session_state.admin_authenticated = False

if "scanner_authenticated" not in st.session_state:
    st.session_state.scanner_authenticated = False

# ============================================================
# CSS
# ============================================================
st.markdown(
    """
    <style>
    .title {font-size:2.25rem;font-weight:800;margin-bottom:.15rem;}
    .subtitle {color:#666;margin-bottom:1rem;}
    .verified-card {
        border:2px solid #1f8f4e;background:#effbf3;
        border-radius:18px;padding:20px;
    }
    .danger-card {
        border:2px solid #b42318;background:#fff3f2;
        border-radius:18px;padding:20px;
    }
    .live-code {
        font-size:2.2rem;font-weight:800;letter-spacing:.3rem;
        background:#111827;color:white;border-radius:12px;
        padding:12px 18px;display:inline-block;
    }
    .official-domain {
        font-family:monospace;background:#f0f2f6;
        padding:5px 8px;border-radius:7px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# PUBLIC QR / SCANNER AUTHENTICATION MODE
# ============================================================
verify_token = st.query_params.get("verify")

if verify_token:
    st.markdown('<div class="title">🛡️ AirNexus Secure QR Verification</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="subtitle">Official verification host: '
        f'<span class="official-domain">{official_host()}</span></div>',
        unsafe_allow_html=True,
    )

    # The QR page is locked until an authorized scanner enters the SCANNER_PASSWORD.
    if not st.session_state.scanner_authenticated:
        st.warning("Authorized event verification staff only.")
        st.info(
            "The QR code has been scanned successfully, but the identity result is protected. "
            "Enter the separate Scanner Password to continue."
        )

        with st.form("scanner_login_form"):
            scanner_password_input = st.text_input(
                "Scanner Password",
                type="password",
                placeholder="Enter authorized scanner password",
            )
            scanner_login = st.form_submit_button(
                "Unlock Verification",
                use_container_width=True,
            )

        if scanner_login:
            if secure_equal(scanner_password_input, SCANNER_PASSWORD):
                st.session_state.scanner_authenticated = True
                st.rerun()
            else:
                st.error("Incorrect Scanner Password.")

        st.caption("This password is separate from the administrator password.")
        st.stop()

    verification_id = f"V-{secrets.token_hex(4).upper()}"
    member = get_member_by_token(verify_token)

    if not member:
        log_scan(None, verification_id, "INVALID_TOKEN")
        st.error("INVALID QR / IDENTITY NOT FOUND")
        st.warning("Do not accept this card.")
        st.write(f"Verification ID: `{verification_id}`")
        if st.button("Lock Scanner", use_container_width=False):
            st.session_state.scanner_authenticated = False
            st.rerun()
        st.stop()

    expiry_ok = True
    if member.get("expiry_date"):
        try:
            expiry_ok = date.fromisoformat(member["expiry_date"]) >= date.today()
        except Exception:
            expiry_ok = True

    is_active = member["status"] == "Active" and expiry_ok
    result = "VERIFIED" if is_active else "NOT_AUTHORIZED"
    log_scan(member, verification_id, result)

    top1, top2 = st.columns([4, 1])
    with top1:
        st.caption("Scanner session is unlocked for authorized staff.")
    with top2:
        if st.button("🔒 Lock Scanner", use_container_width=True):
            st.session_state.scanner_authenticated = False
            st.rerun()

    left, right = st.columns([1, 2])

    with left:
        pimg = photo_image(member.get("photo"))
        if pimg:
            st.image(pimg, caption="Official registered photograph", use_container_width=True)
        else:
            st.warning("No official photograph is registered.")

    with right:
        box_class = "verified-card" if is_active else "danger-card"
        st.markdown(f'<div class="{box_class}">', unsafe_allow_html=True)

        if is_active:
            st.markdown("## ✅ LIVE VERIFIED")
        else:
            st.markdown("## ⛔ NOT AUTHORIZED")

        st.markdown(f"### {member['full_name']}")
        st.markdown(f"**Position:** {safe_text(member['position'])}")
        st.markdown(f"**Category:** {safe_text(member['category'])}")
        st.markdown(f"**Committee / Department:** {safe_text(member['department'])}")
        st.markdown(f"**Card ID:** `{member['card_id']}`")
        st.markdown(f"**Status:** **{member['status']}**")

        if member.get("expiry_date"):
            st.markdown(f"**Valid Until:** {member['expiry_date']}")

        st.markdown("</div>", unsafe_allow_html=True)

        st.write("")
        st.markdown("### Live Anti-Screenshot Code")
        st.markdown(
            f'<span class="live-code">{live_security_code(member["id"])}</span>',
            unsafe_allow_html=True,
        )
        st.caption("This code changes approximately every 30 seconds.")

        st.write(f"**Verification ID:** `{verification_id}`")
        st.write(f"**Verified at:** `{datetime.now().strftime('%d %b %Y, %I:%M:%S %p')}`")
        st.write(f"**QR issue version:** `{member.get('issue_version') or 1}`")

    st.info(
        "Compare the person with the official photo, confirm the physical Card ID, "
        "and make sure this page is opened on the official verification domain."
    )

    if not is_active:
        st.error("This identity is inactive, revoked, lost, or expired. Do not accept it.")

    st.stop()

# ============================================================
# ADMIN AUTHENTICATION
# ============================================================
with st.sidebar:
    st.header("🔐 Administration")

    if not st.session_state.admin_authenticated:
        admin_pw = st.text_input("Admin Password", type="password")
        totp_code = ""

        if ADMIN_TOTP_SECRET:
            totp_code = st.text_input("Authenticator Code", type="password", max_chars=6)

        if st.button("Secure Admin Login", use_container_width=True):
            password_ok = secure_equal(admin_pw, ADMIN_PASSWORD)
            totp_ok = True

            if ADMIN_TOTP_SECRET:
                try:
                    totp_ok = pyotp.TOTP(ADMIN_TOTP_SECRET).verify(totp_code, valid_window=1)
                except Exception:
                    totp_ok = False

            if password_ok and totp_ok:
                st.session_state.admin_authenticated = True
                st.rerun()
            else:
                st.error("Invalid administrator credentials.")
    else:
        st.success("Administrator authenticated")
        if st.button("Logout Admin", use_container_width=True):
            st.session_state.admin_authenticated = False
            st.rerun()

    st.divider()
    st.caption("Scanner access uses a separate password.")

if not st.session_state.admin_authenticated:
    st.markdown('<div class="title">AirNexus Secure Identity Management</div>', unsafe_allow_html=True)
    st.info("Administrator login is required to manage identities.")
    st.caption("Public QR verification is protected by a separate Scanner Password.")
    st.stop()

# ============================================================
# ADMIN DASHBOARD
# ============================================================
st.markdown('<div class="title">AirNexus Secure Identity Management</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">Issue, verify, revoke and audit official event identities.</div>',
    unsafe_allow_html=True,
)

members_df = get_all_members()

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Identities", len(members_df))
m2.metric("Active", int((members_df["status"] == "Active").sum()) if not members_df.empty else 0)
m3.metric("Revoked / Lost", int(members_df["status"].isin(["Revoked", "Lost"]).sum()) if not members_df.empty else 0)
m4.metric("Recent Scan Logs", len(get_recent_scans(500)))

if ADMIN_PASSWORD == "admin123":
    st.error("SECURITY WARNING: Change the default ADMIN_PASSWORD in Streamlit Secrets.")

if SCANNER_PASSWORD == "scanner123":
    st.error("SECURITY WARNING: Change the default SCANNER_PASSWORD in Streamlit Secrets.")

if secure_equal(ADMIN_PASSWORD, SCANNER_PASSWORD):
    st.error("SECURITY WARNING: ADMIN_PASSWORD and SCANNER_PASSWORD must be different.")

if not APP_BASE_URL:
    st.warning("APP_BASE_URL is not configured. Generated QR codes currently point to localhost.")

tabs = st.tabs([
    "➕ Issue Identity",
    "📋 Manage",
    "🔳 QR / Card",
    "🛡️ Scan Logs",
    "📤 Import / Export",
    "📜 Admin Audit",
])

# ============================================================
# TAB 1 - ISSUE IDENTITY
# ============================================================
with tabs[0]:
    st.subheader("Issue New Secure Identity")

    with st.form("new_member_form", clear_on_submit=True):
        c1, c2 = st.columns(2)

        with c1:
            full_name = st.text_input("Full Name *")
            category = st.selectbox(
                "Category *",
                ["Organizer", "Executive Council", "Volunteer", "Guest / Other"],
            )
            position = st.text_input("Position / Designation *")
            department = st.text_input("Committee / Department")
            organization = st.text_input("Organization", value="Air University")
            expiry_date = st.date_input("Valid Until", value=date.today(), format="YYYY-MM-DD")

        with c2:
            email = st.text_input("Email")
            phone = st.text_input("Phone")
            emergency_contact = st.text_input("Emergency Contact")
            blood_group = st.selectbox(
                "Blood Group",
                ["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"],
            )
            manual_card_id = st.text_input("Custom Card ID (optional)")
            photo_file = st.file_uploader(
                "Official Photo *",
                type=["jpg", "jpeg", "png"],
                help="This photo appears on the live verification screen.",
            )
            notes = st.text_area("Public Event Note (optional)")

        submitted = st.form_submit_button("Issue Secure Identity", use_container_width=True)

    if submitted:
        if not full_name.strip() or not position.strip():
            st.error("Full Name and Position are required.")
        elif photo_file is None:
            st.error("An official photograph is required.")
        else:
            member_id = str(uuid.uuid4())
            card_id = manual_card_id.strip() or generate_card_id(category)
            token = new_qr_token()
            now = datetime.now().isoformat(timespec="seconds")

            data = {
                "id": member_id,
                "card_id": card_id,
                "full_name": full_name.strip(),
                "category": category,
                "position": position.strip(),
                "department": department.strip(),
                "organization": organization.strip(),
                "email": email.strip(),
                "phone": phone.strip(),
                "emergency_contact": emergency_contact.strip(),
                "blood_group": blood_group,
                "status": "Active",
                "notes": notes.strip(),
                "created_at": now,
                "photo": photo_file.getvalue(),
                "qr_token_hash": hash_token(token),
                "qr_token_enc": encrypt_token(token),
                "expiry_date": expiry_date.isoformat(),
                "issue_version": 1,
                "last_reissued_at": now,
                "updated_at": now,
            }

            try:
                add_member(data)
                st.success(f"Secure identity issued. Card ID: {card_id}")

                qr_img, verify_url = make_qr_from_token(token)
                card_img = make_id_card(data, token)

                q1, q2 = st.columns([1, 2])

                with q1:
                    st.image(qr_img, width=280)
                    st.code(verify_url)
                    st.download_button(
                        "Download Secure QR",
                        data=png_bytes(qr_img),
                        file_name=f"{card_id}_QR.png",
                        mime="image/png",
                        key=f"new_qr_{member_id}",
                        use_container_width=True,
                    )

                with q2:
                    st.image(card_img, use_container_width=True)
                    st.download_button(
                        "Download ID Card",
                        data=png_bytes(card_img),
                        file_name=f"{card_id}_ID_Card.png",
                        mime="image/png",
                        key=f"new_card_{member_id}",
                        use_container_width=True,
                    )

            except sqlite3.IntegrityError:
                st.error("That Card ID already exists.")

# ============================================================
# TAB 2 - MANAGE
# ============================================================
with tabs[1]:
    st.subheader("Search, Edit, Revoke, Reissue or Delete")

    if members_df.empty:
        st.info("No identities found.")
    else:
        search = st.text_input("Search by name, card ID, role, committee or category").strip().lower()
        filtered = members_df.copy()

        if search:
            mask = False
            for col in ["full_name", "card_id", "position", "department", "category"]:
                mask = mask | filtered[col].fillna("").str.lower().str.contains(search, regex=False)
            filtered = filtered[mask]

        st.dataframe(
            filtered[
                ["card_id", "full_name", "category", "position", "department", "status", "expiry_date", "issue_version"]
            ],
            use_container_width=True,
            hide_index=True,
        )

        if not filtered.empty:
            selected_label = st.selectbox(
                "Select Identity",
                [f"{r.full_name} — {r.position} — {r.card_id}" for r in filtered.itertuples()],
                index=None,
                placeholder="Choose a record",
            )

            if selected_label:
                selected_card_id = selected_label.rsplit(" — ", 1)[-1]
                selected_id = filtered.loc[filtered["card_id"] == selected_card_id, "id"].iloc[0]
                member = get_member_by_id(selected_id)

                pcol, dcol = st.columns([1, 2])

                with pcol:
                    pimg = photo_image(member.get("photo"))
                    if pimg:
                        st.image(pimg, caption="Registered photo", use_container_width=True)
                    else:
                        st.warning("No photo registered.")

                    replacement_photo = st.file_uploader(
                        "Replace Photo",
                        type=["jpg", "jpeg", "png"],
                        key=f"photo_replace_{member['id']}",
                    )
                    if replacement_photo is not None:
                        if st.button("Save New Photo", key=f"save_photo_{member['id']}"):
                            update_photo(member["id"], member["card_id"], replacement_photo.getvalue())
                            st.success("Photo updated.")
                            st.rerun()

                with dcol:
                    with st.form(f"edit_form_{member['id']}"):
                        ec1, ec2 = st.columns(2)

                        with ec1:
                            e_name = st.text_input("Full Name *", value=member["full_name"])
                            categories = ["Organizer", "Executive Council", "Volunteer", "Guest / Other"]
                            e_category = st.selectbox(
                                "Category",
                                categories,
                                index=categories.index(member["category"]) if member["category"] in categories else 0,
                            )
                            e_position = st.text_input("Position", value=member["position"])
                            e_department = st.text_input("Committee / Department", value=member.get("department") or "")
                            e_org = st.text_input("Organization", value=member.get("organization") or "")
                            e_card = st.text_input("Card ID", value=member["card_id"])

                        with ec2:
                            e_email = st.text_input("Email", value=member.get("email") or "")
                            e_phone = st.text_input("Phone", value=member.get("phone") or "")
                            e_emergency = st.text_input("Emergency Contact", value=member.get("emergency_contact") or "")
                            e_bg = st.text_input("Blood Group", value=member.get("blood_group") or "")
                            statuses = ["Active", "Inactive", "Revoked", "Lost"]
                            e_status = st.selectbox(
                                "Status",
                                statuses,
                                index=statuses.index(member["status"]) if member["status"] in statuses else 0,
                            )
                            try:
                                exp_default = date.fromisoformat(member["expiry_date"]) if member.get("expiry_date") else date.today()
                            except Exception:
                                exp_default = date.today()
                            e_expiry = st.date_input("Valid Until", value=exp_default, format="YYYY-MM-DD")
                            e_notes = st.text_area("Public Event Note", value=member.get("notes") or "")

                        save_edit = st.form_submit_button("Save Changes", use_container_width=True)

                    if save_edit:
                        if not e_name.strip() or not e_position.strip():
                            st.error("Name and Position are required.")
                        else:
                            try:
                                update_member(
                                    member["id"],
                                    {
                                        "card_id": e_card.strip(),
                                        "full_name": e_name.strip(),
                                        "category": e_category,
                                        "position": e_position.strip(),
                                        "department": e_department.strip(),
                                        "organization": e_org.strip(),
                                        "email": e_email.strip(),
                                        "phone": e_phone.strip(),
                                        "emergency_contact": e_emergency.strip(),
                                        "blood_group": e_bg.strip(),
                                        "status": e_status,
                                        "notes": e_notes.strip(),
                                        "expiry_date": e_expiry.isoformat(),
                                    },
                                )
                                st.success("Record updated.")
                                st.rerun()
                            except sqlite3.IntegrityError:
                                st.error("That Card ID is already used.")

                st.divider()
                a1, a2, a3 = st.columns(3)

                with a1:
                    if st.button(
                        "Revoke Card",
                        key=f"revoke_{member['id']}",
                        use_container_width=True,
                        disabled=member["status"] == "Revoked",
                    ):
                        set_status(member["id"], member["card_id"], "Revoked")
                        st.success("Identity revoked.")
                        st.rerun()

                with a2:
                    confirm_reissue = st.checkbox(
                        "Invalidate old QR and issue new one",
                        key=f"confirm_reissue_{member['id']}",
                    )
                    if st.button(
                        "Rotate / Reissue QR",
                        key=f"reissue_{member['id']}",
                        use_container_width=True,
                        disabled=not confirm_reissue,
                    ):
                        new_token = reissue_qr(member["id"], member["card_id"])
                        st.session_state[f"fresh_token_{member['id']}"] = new_token
                        st.success("New QR issued. Old QR is invalid.")
                        st.rerun()

                    fresh_token = st.session_state.get(f"fresh_token_{member['id']}")
                    if fresh_token:
                        qi, _ = make_qr_from_token(fresh_token)
                        st.image(qi, width=220)
                        st.download_button(
                            "Download Reissued QR",
                            data=png_bytes(qi),
                            file_name=f"{member['card_id']}_REISSUED_QR.png",
                            mime="image/png",
                            key=f"reissued_download_{member['id']}",
                        )

                with a3:
                    confirm_delete = st.checkbox(
                        "Permanently delete this identity",
                        key=f"confirm_delete_{member['id']}",
                    )
                    if st.button(
                        "Delete Record",
                        key=f"delete_{member['id']}",
                        type="primary",
                        use_container_width=True,
                        disabled=not confirm_delete,
                    ):
                        delete_member(member["id"], member["card_id"])
                        st.success("Record deleted.")
                        st.rerun()

# ============================================================
# TAB 3 - QR / CARD
# ============================================================
with tabs[2]:
    st.subheader("Secure QR and Physical Card Output")

    current = get_all_members()

    if current.empty:
        st.info("No identities available.")
    else:
        label = st.selectbox(
            "Choose Person",
            [f"{r.full_name} — {r.position} — {r.card_id}" for r in current.itertuples()],
            key="card_selector",
        )
        cid = label.rsplit(" — ", 1)[-1]
        member_id = current.loc[current["card_id"] == cid, "id"].iloc[0]
        member = get_member_by_id(member_id)

        token = decrypt_token(member.get("qr_token_enc"))

        if not token:
            st.error("No recoverable QR token. Reissue the QR from Manage.")
        else:
            qr_img, verify_url = make_qr_from_token(token)
            card_img = make_id_card(member, token)

            c1, c2 = st.columns([1, 2])

            with c1:
                st.image(qr_img, width=280)
                st.code(verify_url)
                st.download_button(
                    "Download Secure QR",
                    data=png_bytes(qr_img),
                    file_name=f"{member['card_id']}_QR.png",
                    mime="image/png",
                    key=f"existing_qr_{member['id']}",
                    use_container_width=True,
                )

            with c2:
                st.image(card_img, use_container_width=True)
                st.download_button(
                    "Download ID Card",
                    data=png_bytes(card_img),
                    file_name=f"{member['card_id']}_ID_Card.png",
                    mime="image/png",
                    key=f"existing_card_{member['id']}",
                    use_container_width=True,
                )

# ============================================================
# TAB 4 - SCAN LOGS
# ============================================================
with tabs[3]:
    st.subheader("Verification Scan Log")
    st.dataframe(get_recent_scans(500), use_container_width=True, hide_index=True)

# ============================================================
# TAB 5 - IMPORT / EXPORT
# ============================================================
with tabs[4]:
    st.subheader("Backup / Export")

    export_df = get_all_members()
    if not export_df.empty:
        st.download_button(
            "Download Records CSV",
            data=export_df.to_csv(index=False).encode("utf-8"),
            file_name="airnexus_identity_records.csv",
            mime="text/csv",
            key="records_export",
        )
    else:
        st.info("No records to export.")

    st.divider()
    st.markdown("### Bulk Import")

    template = pd.DataFrame(
        [{
            "full_name": "Example Name",
            "category": "Organizer",
            "position": "Registration Coordinator",
            "department": "Registration Committee",
            "organization": "Air University",
            "email": "example@email.com",
            "phone": "",
            "emergency_contact": "",
            "blood_group": "",
            "status": "Active",
            "notes": "",
            "card_id": "",
            "expiry_date": date.today().isoformat(),
        }]
    )

    st.download_button(
        "Download CSV Template",
        data=template.to_csv(index=False).encode("utf-8"),
        file_name="airnexus_identity_import_template.csv",
        mime="text/csv",
        key="import_template",
    )

    upload = st.file_uploader("Upload CSV", type=["csv"], key="csv_import")

    if upload is not None:
        try:
            df = pd.read_csv(upload).fillna("")
            required = {"full_name", "category", "position"}

            if not required.issubset(df.columns):
                st.error("CSV must include full_name, category and position.")
            else:
                st.dataframe(df.head(25), use_container_width=True, hide_index=True)

                if st.button("Import Identities", key="import_btn"):
                    added = 0
                    skipped = 0

                    for _, row in df.iterrows():
                        full_name = str(row.get("full_name", "")).strip()
                        position = str(row.get("position", "")).strip()
                        category = str(row.get("category", "Organizer")).strip() or "Organizer"

                        if not full_name or not position:
                            skipped += 1
                            continue

                        token = new_qr_token()
                        now = datetime.now().isoformat(timespec="seconds")
                        exp = str(row.get("expiry_date", "")).strip() or date.today().isoformat()
                        card_id = str(row.get("card_id", "")).strip() or generate_card_id(category)

                        data = {
                            "id": str(uuid.uuid4()),
                            "card_id": card_id,
                            "full_name": full_name,
                            "category": category,
                            "position": position,
                            "department": str(row.get("department", "")).strip(),
                            "organization": str(row.get("organization", "")).strip(),
                            "email": str(row.get("email", "")).strip(),
                            "phone": str(row.get("phone", "")).strip(),
                            "emergency_contact": str(row.get("emergency_contact", "")).strip(),
                            "blood_group": str(row.get("blood_group", "")).strip(),
                            "status": str(row.get("status", "Active")).strip() or "Active",
                            "notes": str(row.get("notes", "")).strip(),
                            "created_at": now,
                            "photo": None,
                            "qr_token_hash": hash_token(token),
                            "qr_token_enc": encrypt_token(token),
                            "expiry_date": exp,
                            "issue_version": 1,
                            "last_reissued_at": now,
                            "updated_at": now,
                        }

                        try:
                            add_member(data)
                            added += 1
                        except sqlite3.IntegrityError:
                            skipped += 1

                    st.success(f"Import complete. Added: {added}. Skipped: {skipped}.")
                    st.rerun()

        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")

# ============================================================
# TAB 6 - ADMIN AUDIT
# ============================================================
with tabs[5]:
    st.subheader("Administrator Audit Trail")
    st.dataframe(get_audit_log(500), use_container_width=True, hide_index=True)

st.divider()
st.caption(
    "Production note: Streamlit Community Cloud local SQLite storage is not guaranteed permanent. "
    "For the live event, move the database and photo storage to persistent PostgreSQL/Supabase."
)
