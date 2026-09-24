import base64
import hashlib
import hmac
import io
import secrets
import uuid
from datetime import datetime, date
from urllib.parse import urlparse

import pandas as pd
import pyotp
import qrcode
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image, ImageDraw, ImageFont
from supabase import create_client, Client


# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="AirNexus Secure Identity Verification",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# SECRETS / CONFIG
# ============================================================
def get_secret(name, default=""):
    try:
        value = st.secrets.get(name, default)
        return str(value) if value is not None else default
    except Exception:
        return default


APP_BASE_URL = get_secret("APP_BASE_URL", "").strip().rstrip("/")

ADMIN_PASSWORD = get_secret("ADMIN_PASSWORD", "admin123")
SCANNER_PASSWORD = get_secret("SCANNER_PASSWORD", "scanner123")

ADMIN_TOTP_SECRET = get_secret("ADMIN_TOTP_SECRET", "").strip()

APP_ENCRYPTION_KEY = get_secret("APP_ENCRYPTION_KEY", "").strip()
APP_MASTER_SECRET = get_secret("APP_MASTER_SECRET", "").strip()
LIVE_SECURITY_SECRET = get_secret("LIVE_SECURITY_SECRET", "").strip()

SUPABASE_URL = get_secret("SUPABASE_URL", "").strip()
SUPABASE_KEY = get_secret("SUPABASE_KEY", "").strip()


if not SUPABASE_URL or not SUPABASE_KEY:
    st.error(
        "Supabase is not configured. Add SUPABASE_URL and SUPABASE_KEY "
        "in Streamlit Cloud -> Manage app -> Settings -> Secrets."
    )
    st.stop()


# ============================================================
# SUPABASE CONNECTION
# ============================================================
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as exc:
    st.error(f"Could not connect to Supabase: {exc}")
    st.stop()


# ============================================================
# SECURITY
# ============================================================
def secure_equal(a, b):
    return hmac.compare_digest(str(a), str(b))


def derive_fallback_secret():
    base = APP_MASTER_SECRET or f"{ADMIN_PASSWORD}|{SCANNER_PASSWORD}|airnexus-secure-app"
    return hashlib.sha256(base.encode("utf-8")).digest()


def get_fernet():
    if APP_ENCRYPTION_KEY:
        try:
            return Fernet(APP_ENCRYPTION_KEY.encode("utf-8"))
        except Exception:
            st.error("APP_ENCRYPTION_KEY in Streamlit Secrets is invalid.")
            st.stop()

    key = base64.urlsafe_b64encode(derive_fallback_secret())
    return Fernet(key)


FERNET = get_fernet()


def get_live_secret_bytes():
    if LIVE_SECURITY_SECRET:
        return LIVE_SECURITY_SECRET.encode("utf-8")

    return hashlib.sha256(
        derive_fallback_secret() + b":live-code"
    ).digest()


LIVE_SECRET = get_live_secret_bytes()


# ============================================================
# QR TOKEN SECURITY
# ============================================================
def new_qr_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def encrypt_token(token):
    return FERNET.encrypt(
        token.encode("utf-8")
    ).decode("utf-8")


def decrypt_token(enc):
    if not enc:
        return None

    try:
        return FERNET.decrypt(
            enc.encode("utf-8")
        ).decode("utf-8")
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

    image = qr.make_image(
        fill_color="black",
        back_color="white"
    ).convert("RGB")

    return image, url


def png_bytes(img):
    buff = io.BytesIO()
    img.save(buff, format="PNG")
    return buff.getvalue()


# ============================================================
# PHOTO HELPERS
# ============================================================
def encode_photo(photo_bytes):
    if not photo_bytes:
        return None

    return base64.b64encode(
        photo_bytes
    ).decode("utf-8")


def decode_photo(photo_text):
    if not photo_text:
        return None

    try:
        return base64.b64decode(photo_text)
    except Exception:
        return None


def photo_image(photo_text):
    photo_bytes = decode_photo(photo_text)

    if not photo_bytes:
        return None

    try:
        return Image.open(
            io.BytesIO(photo_bytes)
        ).convert("RGB")
    except Exception:
        return None


# ============================================================
# SUPABASE DATABASE FUNCTIONS
# ============================================================
def add_audit(
    action,
    member_id=None,
    card_id=None,
    details=""
):
    supabase.table(
        "admin_audit"
    ).insert({
        "action": action,
        "member_id": member_id,
        "card_id": card_id,
        "action_time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "details": details,
    }).execute()


def add_member(data):
    supabase.table(
        "members"
    ).insert(
        data
    ).execute()

    add_audit(
        "CREATE_MEMBER",
        data["id"],
        data["card_id"],
        "New identity created",
    )


def update_member(member_id, data):
    update_data = dict(data)

    update_data["updated_at"] = datetime.now().isoformat(
        timespec="seconds"
    )

    supabase.table(
        "members"
    ).update(
        update_data
    ).eq(
        "id",
        member_id
    ).execute()

    add_audit(
        "UPDATE_MEMBER",
        member_id,
        data["card_id"],
        "Identity record updated",
    )


def update_photo(
    member_id,
    card_id,
    photo_bytes
):
    supabase.table(
        "members"
    ).update({
        "photo": encode_photo(photo_bytes),
        "updated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
    }).eq(
        "id",
        member_id
    ).execute()

    add_audit(
        "UPDATE_PHOTO",
        member_id,
        card_id,
        "Photo changed",
    )


def delete_member(
    member_id,
    card_id
):
    supabase.table(
        "members"
    ).delete().eq(
        "id",
        member_id
    ).execute()

    add_audit(
        "DELETE_MEMBER",
        member_id,
        card_id,
        "Identity deleted",
    )


def get_all_members():
    response = (
        supabase
        .table("members")
        .select("*")
        .order("full_name")
        .execute()
    )

    if not response.data:
        return pd.DataFrame(columns=[
            "id",
            "card_id",
            "full_name",
            "category",
            "position",
            "department",
            "organization",
            "email",
            "phone",
            "emergency_contact",
            "blood_group",
            "status",
            "notes",
            "created_at",
            "photo",
            "qr_token_hash",
            "qr_token_enc",
            "expiry_date",
            "issue_version",
            "last_reissued_at",
            "updated_at"
        ])

    return pd.DataFrame(
        response.data
    )


def get_member_by_id(member_id):
    response = (
        supabase
        .table("members")
        .select("*")
        .eq("id", member_id)
        .limit(1)
        .execute()
    )

    if response.data:
        return response.data[0]

    return None


def get_member_by_token(token):
    token_digest = hash_token(token)

    response = (
        supabase
        .table("members")
        .select("*")
        .eq("qr_token_hash", token_digest)
        .limit(1)
        .execute()
    )

    if response.data:
        return response.data[0]

    return None


def reissue_qr(
    member_id,
    card_id
):
    member = get_member_by_id(
        member_id
    )

    if not member:
        return None

    token = new_qr_token()

    next_version = int(
        member.get("issue_version") or 1
    ) + 1

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    supabase.table(
        "members"
    ).update({
        "qr_token_hash": hash_token(token),
        "qr_token_enc": encrypt_token(token),
        "issue_version": next_version,
        "last_reissued_at": now,
        "updated_at": now,
    }).eq(
        "id",
        member_id
    ).execute()

    add_audit(
        "REISSUE_QR",
        member_id,
        card_id,
        f"QR rotated to version {next_version}",
    )

    return token


def set_status(
    member_id,
    card_id,
    status
):
    supabase.table(
        "members"
    ).update({
        "status": status,
        "updated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
    }).eq(
        "id",
        member_id
    ).execute()

    add_audit(
        "STATUS_CHANGE",
        member_id,
        card_id,
        f"Status changed to {status}",
    )


def log_scan(
    member,
    verification_id,
    result
):
    supabase.table(
        "scan_logs"
    ).insert({
        "member_id": member["id"] if member else None,
        "card_id": member["card_id"] if member else None,
        "scan_time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "verification_id": verification_id,
        "result": result,
    }).execute()


def get_recent_scans(
    limit=500
):
    response = (
        supabase
        .table("scan_logs")
        .select("*")
        .order("id", desc=True)
        .limit(limit)
        .execute()
    )

    if not response.data:
        return pd.DataFrame(columns=[
            "scan_time",
            "card_id",
            "verification_id",
            "result"
        ])

    df = pd.DataFrame(
        response.data
    )

    wanted = [
        col
        for col in [
            "scan_time",
            "card_id",
            "verification_id",
            "result"
        ]
        if col in df.columns
    ]

    return df[wanted]


def get_audit_log(
    limit=500
):
    response = (
        supabase
        .table("admin_audit")
        .select("*")
        .order("id", desc=True)
        .limit(limit)
        .execute()
    )

    if not response.data:
        return pd.DataFrame(columns=[
            "action_time",
            "action",
            "card_id",
            "details"
        ])

    df = pd.DataFrame(
        response.data
    )

    wanted = [
        col
        for col in [
            "action_time",
            "action",
            "card_id",
            "details"
        ]
        if col in df.columns
    ]

    return df[wanted]


# ============================================================
# GENERAL HELPERS
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
    }.get(
        category,
        "ID"
    )

    return f"AX-{prefix}-{secrets.token_hex(3).upper()}"


def official_host():
    if not APP_BASE_URL:
        return "localhost / development"

    try:
        return urlparse(
            APP_BASE_URL
        ).netloc or APP_BASE_URL

    except Exception:
        return APP_BASE_URL


def live_security_code(
    member_id
):
    window = int(
        datetime.now().timestamp() // 30
    )

    msg = f"{member_id}:{window}".encode(
        "utf-8"
    )

    digest = hmac.new(
        LIVE_SECRET,
        msg,
        hashlib.sha256
    ).hexdigest()

    return f"{int(digest[:12], 16) % 1000000:06d}"


def make_id_card(
    member,
    token
):
    width, height = 1050, 650

    card = Image.new(
        "RGB",
        (width, height),
        "white"
    )

    draw = ImageDraw.Draw(
        card
    )

    try:
        title_font = ImageFont.truetype(
            "DejaVuSans-Bold.ttf",
            46
        )

        name_font = ImageFont.truetype(
            "DejaVuSans-Bold.ttf",
            40
        )

        normal_font = ImageFont.truetype(
            "DejaVuSans.ttf",
            28
        )

        small_font = ImageFont.truetype(
            "DejaVuSans.ttf",
            22
        )

    except Exception:
        title_font = ImageFont.load_default()
        name_font = ImageFont.load_default()
        normal_font = ImageFont.load_default()
        small_font = ImageFont.load_default()

    draw.rectangle(
        [0, 0, width, 110],
        fill=(18, 43, 84)
    )

    draw.text(
        (40, 30),
        "AIRNEXUS OFFICIAL IDENTITY CARD",
        fill="white",
        font=title_font
    )

    pimg = photo_image(
        member.get("photo")
    )

    if pimg:
        pimg.thumbnail(
            (230, 260)
        )

        px = 55 + (
            230 - pimg.width
        ) // 2

        py = 160 + (
            260 - pimg.height
        ) // 2

        card.paste(
            pimg,
            (px, py)
        )

    else:
        draw.rectangle(
            [55, 160, 285, 420],
            outline=(60, 60, 60),
            width=2
        )

        draw.text(
            (95, 275),
            "PHOTO",
            fill=(100, 100, 100),
            font=normal_font
        )

    draw.text(
        (330, 165),
        member["full_name"],
        fill=(10, 10, 10),
        font=name_font
    )

    draw.text(
        (330, 225),
        member["position"],
        fill=(25, 55, 100),
        font=normal_font
    )

    draw.text(
        (330, 285),
        f"Category: {member['category']}",
        fill=(30, 30, 30),
        font=small_font
    )

    draw.text(
        (330, 325),
        f"Committee: {member.get('department') or '-'}",
        fill=(30, 30, 30),
        font=small_font
    )

    draw.text(
        (330, 365),
        f"Card ID: {member['card_id']}",
        fill=(30, 30, 30),
        font=small_font
    )

    draw.text(
        (330, 405),
        f"Status: {member['status']}",
        fill=(30, 30, 30),
        font=small_font
    )

    qr_img, _ = make_qr_from_token(
        token
    )

    qr_img = qr_img.resize(
        (230, 230)
    )

    card.paste(
        qr_img,
        (785, 165)
    )

    draw.text(
        (770, 410),
        "SCAN FOR LIVE",
        fill=(20, 20, 20),
        font=small_font
    )

    draw.text(
        (790, 445),
        "VERIFICATION",
        fill=(20, 20, 20),
        font=small_font
    )

    draw.rectangle(
        [0, 540, width, 650],
        fill=(245, 247, 250)
    )

    draw.text(
        (40, 565),
        f"Official verification: {official_host()}",
        fill=(60, 60, 60),
        font=small_font
    )

    draw.text(
        (40, 605),
        f"Issue Version: {member.get('issue_version') or 1}",
        fill=(60, 60, 60),
        font=small_font
    )

    return card


# ============================================================
# SESSION STATE
# ============================================================
if "admin_authenticated" not in st.session_state:
    st.session_state.admin_authenticated = False

if "scanner_authenticated" not in st.session_state:
    st.session_state.scanner_authenticated = False


# ============================================================
# PUBLIC QR VERIFICATION MODE
# ============================================================
verify_token = st.query_params.get(
    "verify"
)

if verify_token:

    st.title(
        "🛡️ AirNexus Secure QR Verification"
    )

    st.caption(
        f"Official verification host: {official_host()}"
    )

    if not st.session_state.scanner_authenticated:

        st.warning(
            "Authorized event verification staff only."
        )

        with st.form(
            "scanner_login_form"
        ):

            scanner_password_input = st.text_input(
                "Scanner Password",
                type="password"
            )

            scanner_login = st.form_submit_button(
                "Unlock Verification",
                use_container_width=True
            )

        if scanner_login:

            if secure_equal(
                scanner_password_input,
                SCANNER_PASSWORD
            ):

                st.session_state.scanner_authenticated = True

                st.rerun()

            else:

                st.error(
                    "Incorrect Scanner Password."
                )

        st.stop()


    verification_id = (
        f"V-{secrets.token_hex(4).upper()}"
    )

    member = get_member_by_token(
        verify_token
    )

    if not member:

        try:
            log_scan(
                None,
                verification_id,
                "INVALID_TOKEN"
            )

        except Exception:
            pass

        st.error(
            "INVALID QR / IDENTITY NOT FOUND"
        )

        st.warning(
            "Do not accept this card."
        )

        st.stop()


    expiry_ok = True

    if member.get(
        "expiry_date"
    ):

        try:
            expiry_ok = (
                date.fromisoformat(
                    member["expiry_date"]
                )
                >= date.today()
            )

        except Exception:
            expiry_ok = True


    is_active = (
        member["status"] == "Active"
        and expiry_ok
    )

    result = (
        "VERIFIED"
        if is_active
        else "NOT_AUTHORIZED"
    )


    try:
        log_scan(
            member,
            verification_id,
            result
        )

    except Exception:
        pass


    if st.button(
        "🔒 Lock Scanner"
    ):

        st.session_state.scanner_authenticated = False

        st.rerun()


    left, right = st.columns(
        [1, 2]
    )


    with left:

        pimg = photo_image(
            member.get(
                "photo"
            )
        )

        if pimg:

            st.image(
                pimg,
                caption="Official registered photograph",
                use_container_width=True
            )

        else:

            st.warning(
                "No official photograph is registered."
            )


    with right:

        if is_active:

            st.success(
                "✅ LIVE VERIFIED"
            )

        else:

            st.error(
                "⛔ NOT AUTHORIZED"
            )


        st.header(
            member["full_name"]
        )

        st.write(
            f"**Position:** {safe_text(member['position'])}"
        )

        st.write(
            f"**Category:** {safe_text(member['category'])}"
        )

        st.write(
            f"**Committee / Department:** {safe_text(member['department'])}"
        )

        st.write(
            f"**Card ID:** `{member['card_id']}`"
        )

        st.write(
            f"**Status:** **{member['status']}**"
        )

        if member.get(
            "expiry_date"
        ):

            st.write(
                f"**Valid Until:** {member['expiry_date']}"
            )


        st.subheader(
            "Live Anti-Screenshot Code"
        )

        st.code(
            live_security_code(
                member["id"]
            )
        )

        st.caption(
            "This code changes approximately every 30 seconds."
        )

        st.write(
            f"**Verification ID:** `{verification_id}`"
        )

        st.write(
            f"**Verified at:** "
            f"`{datetime.now().strftime('%d %b %Y, %I:%M:%S %p')}`"
        )


    st.info(
        "Compare the person with the official photo, confirm the Card ID "
        "printed on the physical card, and verify the official domain."
    )


    if not is_active:

        st.error(
            "This identity is inactive, revoked, lost, or expired."
        )


    st.stop()


# ============================================================
# ADMIN LOGIN
# ============================================================
with st.sidebar:

    st.header(
        "🔐 Administration"
    )


    if not st.session_state.admin_authenticated:

        admin_pw = st.text_input(
            "Admin Password",
            type="password"
        )


        totp_code = ""

        if ADMIN_TOTP_SECRET:

            totp_code = st.text_input(
                "Authenticator Code",
                type="password",
                max_chars=6
            )


        if st.button(
            "Secure Admin Login",
            use_container_width=True
        ):

            password_ok = secure_equal(
                admin_pw,
                ADMIN_PASSWORD
            )

            totp_ok = True


            if ADMIN_TOTP_SECRET:

                try:

                    totp_ok = pyotp.TOTP(
                        ADMIN_TOTP_SECRET
                    ).verify(
                        totp_code,
                        valid_window=1
                    )

                except Exception:

                    totp_ok = False


            if password_ok and totp_ok:

                st.session_state.admin_authenticated = True

                st.rerun()

            else:

                st.error(
                    "Invalid administrator credentials."
                )

    else:

        st.success(
            "Administrator authenticated"
        )


        if st.button(
            "Logout Admin",
            use_container_width=True
        ):

            st.session_state.admin_authenticated = False

            st.rerun()


if not st.session_state.admin_authenticated:

    st.title(
        "AirNexus Secure Identity Management"
    )

    st.info(
        "Administrator login is required to manage identities."
    )

    st.stop()


# ============================================================
# DASHBOARD
# ============================================================
st.title(
    "AirNexus Secure Identity Management"
)

st.caption(
    "Issue, verify, revoke and audit official event identities."
)


members_df = get_all_members()


m1, m2, m3 = st.columns(
    3
)

m1.metric(
    "Total Identities",
    len(members_df)
)

m2.metric(
    "Active",
    int(
        (
            members_df["status"]
            == "Active"
        ).sum()
    )
    if not members_df.empty
    else 0
)

m3.metric(
    "Revoked / Lost",
    int(
        members_df["status"].isin(
            [
                "Revoked",
                "Lost"
            ]
        ).sum()
    )
    if not members_df.empty
    else 0
)


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

    st.subheader(
        "Issue New Secure Identity"
    )


    with st.form(
        "new_member_form",
        clear_on_submit=True
    ):

        c1, c2 = st.columns(2)


        with c1:

            full_name = st.text_input(
                "Full Name *"
            )

            category = st.selectbox(
                "Category *",
                [
                    "Organizer",
                    "Executive Council",
                    "Volunteer",
                    "Guest / Other"
                ]
            )

            position = st.text_input(
                "Position / Designation *"
            )

            department = st.text_input(
                "Committee / Department"
            )

            organization = st.text_input(
                "Organization",
                value="Air University"
            )

            expiry_date = st.date_input(
                "Valid Until",
                value=date.today()
            )


        with c2:

            email = st.text_input(
                "Email"
            )

            phone = st.text_input(
                "Phone"
            )

            emergency_contact = st.text_input(
                "Emergency Contact"
            )

            blood_group = st.selectbox(
                "Blood Group",
                [
                    "",
                    "A+",
                    "A-",
                    "B+",
                    "B-",
                    "AB+",
                    "AB-",
                    "O+",
                    "O-"
                ]
            )

            manual_card_id = st.text_input(
                "Custom Card ID (optional)"
            )

            photo_file = st.file_uploader(
                "Official Photo *",
                type=[
                    "jpg",
                    "jpeg",
                    "png"
                ]
            )

            notes = st.text_area(
                "Public Event Note"
            )


        submitted = st.form_submit_button(
            "Issue Secure Identity",
            use_container_width=True
        )


    if submitted:

        if (
            not full_name.strip()
            or not position.strip()
        ):

            st.error(
                "Full Name and Position are required."
            )


        elif photo_file is None:

            st.error(
                "Official photo is required."
            )


        else:

            member_id = str(
                uuid.uuid4()
            )

            card_id = (
                manual_card_id.strip()
                or generate_card_id(
                    category
                )
            )

            token = new_qr_token()

            now = datetime.now().isoformat(
                timespec="seconds"
            )


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

                "photo": encode_photo(
                    photo_file.getvalue()
                ),

                "qr_token_hash": hash_token(
                    token
                ),

                "qr_token_enc": encrypt_token(
                    token
                ),

                "expiry_date": expiry_date.isoformat(),

                "issue_version": 1,

                "last_reissued_at": now,

                "updated_at": now,
            }


            try:

                add_member(
                    data
                )

                st.success(
                    f"Identity created. Card ID: {card_id}"
                )


                qr_img, verify_url = make_qr_from_token(
                    token
                )

                card_img = make_id_card(
                    data,
                    token
                )


                c1, c2 = st.columns(
                    [1, 2]
                )


                with c1:

                    st.image(
                        qr_img,
                        width=280
                    )

                    st.code(
                        verify_url
                    )

                    st.download_button(
                        "Download QR",
                        data=png_bytes(
                            qr_img
                        ),
                        file_name=f"{card_id}_QR.png",
                        mime="image/png",
                    )


                with c2:

                    st.image(
                        card_img,
                        use_container_width=True
                    )

                    st.download_button(
                        "Download ID Card",
                        data=png_bytes(
                            card_img
                        ),
                        file_name=f"{card_id}_Card.png",
                        mime="image/png",
                    )


            except Exception as exc:

                st.error(
                    f"Could not create identity: {exc}"
                )


# ============================================================
# TAB 2 - MANAGE
# ============================================================
with tabs[1]:

    st.subheader(
        "Manage Identities"
    )


    if members_df.empty:

        st.info(
            "No identities available."
        )


    else:

        selected_label = st.selectbox(
            "Select Identity",
            [
                f"{r.full_name} — {r.card_id}"
                for r
                in members_df.itertuples()
            ],
            index=None
        )


        if selected_label:

            selected_card_id = selected_label.rsplit(
                " — ",
                1
            )[-1]


            member_id = members_df.loc[
                members_df["card_id"]
                == selected_card_id,
                "id"
            ].iloc[0]


            member = get_member_by_id(
                member_id
            )


            pimg = photo_image(
                member.get(
                    "photo"
                )
            )


            if pimg:

                st.image(
                    pimg,
                    width=200
                )


            st.write(
                f"**Name:** {member['full_name']}"
            )

            st.write(
                f"**Position:** {member['position']}"
            )

            st.write(
                f"**Status:** {member['status']}"
            )


            c1, c2, c3 = st.columns(
                3
            )


            with c1:

                if st.button(
                    "Revoke Card"
                ):

                    set_status(
                        member["id"],
                        member["card_id"],
                        "Revoked"
                    )

                    st.success(
                        "Card revoked."
                    )

                    st.rerun()


            with c2:

                if st.button(
                    "Reissue QR"
                ):

                    new_token = reissue_qr(
                        member["id"],
                        member["card_id"]
                    )

                    st.success(
                        "New QR issued. Old QR is invalid."
                    )

                    qr_img, _ = make_qr_from_token(
                        new_token
                    )

                    st.image(
                        qr_img,
                        width=220
                    )


            with c3:

                if st.button(
                    "Delete Record"
                ):

                    delete_member(
                        member["id"],
                        member["card_id"]
                    )

                    st.success(
                        "Record deleted."
                    )

                    st.rerun()


# ============================================================
# TAB 3 - QR / CARD
# ============================================================
with tabs[2]:

    st.subheader(
        "QR and Card"
    )


    if not members_df.empty:

        label = st.selectbox(
            "Choose Person",
            [
                f"{r.full_name} — {r.card_id}"
                for r
                in members_df.itertuples()
            ],
            key="qr_select"
        )


        cid = label.rsplit(
            " — ",
            1
        )[-1]


        member_id = members_df.loc[
            members_df["card_id"]
            == cid,
            "id"
        ].iloc[0]


        member = get_member_by_id(
            member_id
        )


        token = decrypt_token(
            member.get(
                "qr_token_enc"
            )
        )


        if token:

            qr_img, verify_url = make_qr_from_token(
                token
            )

            card_img = make_id_card(
                member,
                token
            )


            st.image(
                qr_img,
                width=280
            )

            st.code(
                verify_url
            )

            st.download_button(
                "Download QR",
                data=png_bytes(
                    qr_img
                ),
                file_name=f"{cid}_QR.png",
                mime="image/png",
            )


            st.image(
                card_img,
                use_container_width=True
            )

            st.download_button(
                "Download Card",
                data=png_bytes(
                    card_img
                ),
                file_name=f"{cid}_Card.png",
                mime="image/png",
            )


# ============================================================
# TAB 4 - SCAN LOGS
# ============================================================
with tabs[3]:

    st.subheader(
        "Scan Logs"
    )

    st.dataframe(
        get_recent_scans(),
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# TAB 5 - EXPORT
# ============================================================
with tabs[4]:

    st.subheader(
        "Export Records"
    )


    if not members_df.empty:

        st.download_button(
            "Download CSV",
            data=members_df.to_csv(
                index=False
            ).encode(
                "utf-8"
            ),
            file_name="airnexus_records.csv",
            mime="text/csv",
        )


# ============================================================
# TAB 6 - AUDIT
# ============================================================
with tabs[5]:

    st.subheader(
        "Admin Audit Log"
    )

    st.dataframe(
        get_audit_log(),
        use_container_width=True,
        hide_index=True
    )


st.divider()

st.caption(
    "AirNexus data is stored in Supabase PostgreSQL."
)
