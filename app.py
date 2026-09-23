import io
import os
import sqlite3
import uuid
from datetime import datetime

import pandas as pd
import qrcode
import streamlit as st
from PIL import Image, ImageDraw, ImageFont

# -----------------------------
# PAGE CONFIG
# -----------------------------
st.set_page_config(
    page_title="Event Identity & QR Management",
    page_icon="🎫",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# CONFIGURATION
# -----------------------------
DB_FILE = "event_identity.db"

def get_secret(name, default=""):
    try:
        return st.secrets.get(name, default)
    except Exception:
        return default

APP_BASE_URL = get_secret("APP_BASE_URL", "").strip().rstrip("/")
ADMIN_PASSWORD = get_secret("ADMIN_PASSWORD", "admin123")

# -----------------------------
# DATABASE
# -----------------------------
def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
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
    conn.commit()
    conn.close()

def add_member(data):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO members (
            id, card_id, full_name, category, position, department,
            organization, email, phone, emergency_contact, blood_group,
            status, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data["id"],
            data["card_id"],
            data["full_name"],
            data["category"],
            data["position"],
            data["department"],
            data["organization"],
            data["email"],
            data["phone"],
            data["emergency_contact"],
            data["blood_group"],
            data["status"],
            data["notes"],
            data["created_at"],
        ),
    )
    conn.commit()
    conn.close()

def update_member(member_id, data):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE members SET
            card_id = ?,
            full_name = ?,
            category = ?,
            position = ?,
            department = ?,
            organization = ?,
            email = ?,
            phone = ?,
            emergency_contact = ?,
            blood_group = ?,
            status = ?,
            notes = ?
        WHERE id = ?
        """,
        (
            data["card_id"],
            data["full_name"],
            data["category"],
            data["position"],
            data["department"],
            data["organization"],
            data["email"],
            data["phone"],
            data["emergency_contact"],
            data["blood_group"],
            data["status"],
            data["notes"],
            member_id,
        ),
    )
    conn.commit()
    conn.close()

def delete_member(member_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM members WHERE id = ?", (member_id,))
    conn.commit()
    conn.close()

def get_member(member_id):
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT * FROM members WHERE id = ?",
        conn,
        params=(member_id,),
    )
    conn.close()
    if df.empty:
        return None
    return df.iloc[0].to_dict()

def get_all_members():
    conn = get_connection()
    df = pd.read_sql_query(
        """
        SELECT * FROM members
        ORDER BY
            CASE WHEN category = 'Executive Council' THEN 1
                 WHEN category = 'Organizer' THEN 2
                 ELSE 3 END,
            full_name
        """,
        conn,
    )
    conn.close()
    return df

init_db()

# -----------------------------
# HELPERS
# -----------------------------
def build_profile_url(member_id):
    if APP_BASE_URL:
        return f"{APP_BASE_URL}/?member={member_id}"
    return f"http://localhost:8501/?member={member_id}"

def make_qr_image(member_id):
    profile_url = build_profile_url(member_id)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(profile_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return img, profile_url

def image_to_png_bytes(img):
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

def make_id_card(member):
    width, height = 1050, 650
    card = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(card)

    try:
        title_font = ImageFont.truetype("DejaVuSans-Bold.ttf", 52)
        name_font = ImageFont.truetype("DejaVuSans-Bold.ttf", 45)
        normal_font = ImageFont.truetype("DejaVuSans.ttf", 32)
        small_font = ImageFont.truetype("DejaVuSans.ttf", 25)
    except Exception:
        title_font = ImageFont.load_default()
        name_font = ImageFont.load_default()
        normal_font = ImageFont.load_default()
        small_font = ImageFont.load_default()

    draw.rectangle([0, 0, width, 120], fill=(25, 45, 85))
    draw.text((45, 32), "EVENT OFFICIAL IDENTITY CARD", fill="white", font=title_font)

    draw.text((55, 165), member["full_name"], fill=(15, 15, 15), font=name_font)
    draw.text((55, 235), member["position"], fill=(35, 55, 95), font=normal_font)

    draw.text((55, 300), f"Category: {member['category']}", fill=(30, 30, 30), font=small_font)
    draw.text((55, 345), f"Department: {member.get('department') or '-'}", fill=(30, 30, 30), font=small_font)
    draw.text((55, 390), f"Organization: {member.get('organization') or '-'}", fill=(30, 30, 30), font=small_font)
    draw.text((55, 435), f"Card ID: {member['card_id']}", fill=(30, 30, 30), font=small_font)
    draw.text((55, 480), f"Status: {member['status']}", fill=(30, 30, 30), font=small_font)

    qr_img, _ = make_qr_image(member["id"])
    qr_img = qr_img.resize((300, 300))
    card.paste(qr_img, (700, 180))

    draw.text((720, 500), "Scan to verify identity", fill=(30, 30, 30), font=small_font)
    draw.text((55, 585), "Generated by Event Identity & QR Management System", fill=(80, 80, 80), font=small_font)

    return card

def generate_card_id(category):
    prefix = "EC" if category == "Executive Council" else "ORG"
    random_part = uuid.uuid4().hex[:6].upper()
    return f"{prefix}-{random_part}"

def safe_text(value):
    if value is None:
        return "-"
    value = str(value).strip()
    return value if value else "-"

# -----------------------------
# STYLING
# -----------------------------
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
    }
    .subtitle {
        color: #666;
        margin-bottom: 1.3rem;
    }
    .profile-box {
        padding: 1.4rem;
        border: 1px solid #dedede;
        border-radius: 14px;
        background: #ffffff;
    }
    .verified {
        display:inline-block;
        padding:7px 12px;
        background:#e8f7ed;
        border-radius:20px;
        color:#19713a;
        font-weight:700;
    }
    .inactive {
        display:inline-block;
        padding:7px 12px;
        background:#fff0f0;
        border-radius:20px;
        color:#a82121;
        font-weight:700;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------
# PUBLIC PROFILE MODE
# -----------------------------
member_param = st.query_params.get("member")

if member_param:
    member = get_member(member_param)

    st.markdown('<div class="main-title">Official Event Identity Verification</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="subtitle">This page verifies the identity and event role associated with the scanned QR code.</div>',
        unsafe_allow_html=True,
    )

    if not member:
        st.error("Invalid or expired identity record. Please contact the event administration.")
        st.stop()

    left, right = st.columns([2, 1])

    with left:
        st.markdown('<div class="profile-box">', unsafe_allow_html=True)
        st.header(member["full_name"])
        st.subheader(member["position"])

        if member["status"] == "Active":
            st.markdown('<span class="verified">✓ ACTIVE / VERIFIED</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="inactive">INACTIVE / NOT AUTHORIZED</span>', unsafe_allow_html=True)

        st.write("")
        st.write(f"**Category:** {safe_text(member['category'])}")
        st.write(f"**Department / Committee:** {safe_text(member['department'])}")
        st.write(f"**Organization / Institution:** {safe_text(member['organization'])}")
        st.write(f"**Card ID:** `{member['card_id']}`")

        if safe_text(member.get("notes")) != "-":
            st.write(f"**Event Note:** {safe_text(member.get('notes'))}")

        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        qr_img, _ = make_qr_image(member["id"])
        st.image(qr_img, caption="Official verification QR", width=280)
        st.caption("The QR code links to this verification page.")

    st.info("For security, private contact information is not displayed on the public verification page.")
    st.stop()

# -----------------------------
# ADMIN / DASHBOARD MODE
# -----------------------------
st.markdown('<div class="main-title">Event Identity & QR Management</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">Manage organizers and executive council members, issue QR identities, and verify event roles.</div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Administration")
    password = st.text_input("Admin Password", type="password")
    logged_in = password == ADMIN_PASSWORD

    if logged_in:
        st.success("Administrator access granted")
    elif password:
        st.error("Incorrect password")

    st.divider()
    st.caption("Public QR scans do not require the admin password.")

if not logged_in:
    st.info("Enter the administrator password in the sidebar to manage records.")
    st.warning(
        "Before public deployment, set ADMIN_PASSWORD and APP_BASE_URL in Streamlit Secrets. "
        "Do not keep the default password."
    )
    st.stop()

members_df = get_all_members()

# -----------------------------
# METRICS
# -----------------------------
c1, c2, c3, c4 = st.columns(4)

total_members = len(members_df)
active_members = int((members_df["status"] == "Active").sum()) if not members_df.empty else 0
executives = int((members_df["category"] == "Executive Council").sum()) if not members_df.empty else 0
organizers = int((members_df["category"] == "Organizer").sum()) if not members_df.empty else 0

c1.metric("Total Records", total_members)
c2.metric("Active Identities", active_members)
c3.metric("Executive Council", executives)
c4.metric("Organizers", organizers)

tab1, tab2, tab3, tab4 = st.tabs(
    ["➕ Add Record", "📋 Manage Records", "🔳 QR / ID Cards", "📤 Import / Export"]
)

# -----------------------------
# ADD RECORD
# -----------------------------
with tab1:
    st.subheader("Add New Person")

    with st.form("add_member_form", clear_on_submit=True):
        col1, col2 = st.columns(2)

        with col1:
            full_name = st.text_input("Full Name *")
            category = st.selectbox(
                "Category *",
                ["Organizer", "Executive Council", "Volunteer", "Guest / Other"],
            )
            position = st.text_input(
                "Position / Designation *",
                placeholder="e.g. President, General Secretary, Event Organizer",
            )
            department = st.text_input(
                "Department / Committee",
                placeholder="e.g. Registration Committee",
            )
            organization = st.text_input(
                "Organization / Institution",
                placeholder="e.g. Air University",
            )
            status = st.selectbox("Identity Status", ["Active", "Inactive"])

        with col2:
            email = st.text_input("Email")
            phone = st.text_input("Phone")
            emergency_contact = st.text_input("Emergency Contact")
            blood_group = st.selectbox(
                "Blood Group",
                ["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"],
            )
            manual_card_id = st.text_input(
                "Custom Card ID (optional)",
                placeholder="Leave blank to auto-generate",
            )
            notes = st.text_area(
                "Public Event Note (optional)",
                placeholder="Only write information here that may safely appear on the QR verification page.",
            )

        submitted = st.form_submit_button(
            "Create Record & QR",
            use_container_width=True
        )

    # IMPORTANT:
    # The download button is outside the form.
    if submitted:
        if not full_name.strip() or not position.strip():
            st.error("Full Name and Position / Designation are required.")
        else:
            member_id = str(uuid.uuid4())
            card_id = manual_card_id.strip() or generate_card_id(category)

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
                "status": status,
                "notes": notes.strip(),
                "created_at": datetime.now().isoformat(timespec="seconds"),
            }

            try:
                add_member(data)

                st.success(f"Record created successfully. Card ID: {card_id}")

                qr_img, profile_url = make_qr_image(member_id)

                st.markdown("### Generated QR Code")
                st.image(qr_img, width=260)

                st.markdown("### Verification URL")
                st.code(profile_url)

                qr_bytes = image_to_png_bytes(qr_img)

                st.download_button(
                    label="⬇️ Download QR Code",
                    data=qr_bytes,
                    file_name=f"{card_id}_QR.png",
                    mime="image/png",
                    key=f"download_qr_{member_id}",
                    use_container_width=True,
                )

            except sqlite3.IntegrityError:
                st.error("That Card ID already exists. Please use another Card ID.")

# -----------------------------
# MANAGE RECORDS
# -----------------------------
with tab2:
    st.subheader("Search, Edit or Delete Records")

    if members_df.empty:
        st.info("No records have been created yet.")
    else:
        search = st.text_input(
            "Search",
            placeholder="Search by name, card ID, position, category or department",
        ).strip().lower()

        filtered = members_df.copy()

        if search:
            mask = (
                filtered["full_name"].fillna("").str.lower().str.contains(search, regex=False)
                | filtered["card_id"].fillna("").str.lower().str.contains(search, regex=False)
                | filtered["position"].fillna("").str.lower().str.contains(search, regex=False)
                | filtered["category"].fillna("").str.lower().str.contains(search, regex=False)
                | filtered["department"].fillna("").str.lower().str.contains(search, regex=False)
            )
            filtered = filtered[mask]

        display_cols = [
            "card_id",
            "full_name",
            "category",
            "position",
            "department",
            "status",
            "created_at",
        ]

        st.dataframe(
            filtered[display_cols],
            use_container_width=True,
            hide_index=True,
        )

        if not filtered.empty:
            selected_label = st.selectbox(
                "Select Record",
                [
                    f"{row.full_name} — {row.position} — {row.card_id}"
                    for row in filtered.itertuples()
                ],
                index=None,
                placeholder="Choose a record to edit or delete",
            )

            if selected_label:
                selected_card_id = selected_label.rsplit(" — ", 1)[-1]
                selected_row = filtered[filtered["card_id"] == selected_card_id].iloc[0].to_dict()

                st.divider()
                st.markdown(f"### Edit: {selected_row['full_name']}")

                with st.form("edit_member_form"):
                    e1, e2 = st.columns(2)

                    with e1:
                        e_full_name = st.text_input("Full Name *", value=safe_text(selected_row["full_name"]))
                        categories = ["Organizer", "Executive Council", "Volunteer", "Guest / Other"]
                        current_category = selected_row["category"]
                        e_category = st.selectbox(
                            "Category *",
                            categories,
                            index=categories.index(current_category) if current_category in categories else 0,
                        )
                        e_position = st.text_input("Position / Designation *", value=safe_text(selected_row["position"]))
                        e_department = st.text_input("Department / Committee", value="" if safe_text(selected_row["department"]) == "-" else safe_text(selected_row["department"]))
                        e_organization = st.text_input("Organization / Institution", value="" if safe_text(selected_row["organization"]) == "-" else safe_text(selected_row["organization"]))
                        statuses = ["Active", "Inactive"]
                        e_status = st.selectbox(
                            "Identity Status",
                            statuses,
                            index=statuses.index(selected_row["status"]) if selected_row["status"] in statuses else 0,
                        )

                    with e2:
                        e_email = st.text_input("Email", value="" if safe_text(selected_row["email"]) == "-" else safe_text(selected_row["email"]))
                        e_phone = st.text_input("Phone", value="" if safe_text(selected_row["phone"]) == "-" else safe_text(selected_row["phone"]))
                        e_emergency = st.text_input("Emergency Contact", value="" if safe_text(selected_row["emergency_contact"]) == "-" else safe_text(selected_row["emergency_contact"]))
                        blood_groups = ["", "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
                        current_bg = selected_row["blood_group"] if selected_row["blood_group"] in blood_groups else ""
                        e_blood = st.selectbox("Blood Group", blood_groups, index=blood_groups.index(current_bg))
                        e_card_id = st.text_input("Card ID", value=safe_text(selected_row["card_id"]))
                        e_notes = st.text_area("Public Event Note", value="" if safe_text(selected_row["notes"]) == "-" else safe_text(selected_row["notes"]))

                    save_edit = st.form_submit_button("Save Changes", use_container_width=True)

                if save_edit:
                    if not e_full_name.strip() or not e_position.strip():
                        st.error("Full Name and Position / Designation are required.")
                    else:
                        update_data = {
                            "card_id": e_card_id.strip(),
                            "full_name": e_full_name.strip(),
                            "category": e_category,
                            "position": e_position.strip(),
                            "department": e_department.strip(),
                            "organization": e_organization.strip(),
                            "email": e_email.strip(),
                            "phone": e_phone.strip(),
                            "emergency_contact": e_emergency.strip(),
                            "blood_group": e_blood,
                            "status": e_status,
                            "notes": e_notes.strip(),
                        }

                        try:
                            update_member(selected_row["id"], update_data)
                            st.success("Record updated successfully.")
                            st.rerun()
                        except sqlite3.IntegrityError:
                            st.error("That Card ID is already being used by another record.")

                st.markdown("#### Delete Record")
                st.warning("Deleting the record will make its existing QR code invalid.")
                confirm_delete = st.checkbox(
                    f"I confirm that I want to delete {selected_row['full_name']}",
                    key=f"delete_{selected_row['id']}",
                )

                if st.button(
                    "Delete Record",
                    type="primary",
                    disabled=not confirm_delete,
                    key=f"delete_button_{selected_row['id']}"
                ):
                    delete_member(selected_row["id"])
                    st.success("Record deleted.")
                    st.rerun()

# -----------------------------
# QR / ID CARDS
# -----------------------------
with tab3:
    st.subheader("Generate QR Codes and Printable Identity Cards")

    current_members = get_all_members()

    if current_members.empty:
        st.info("Add at least one record first.")
    else:
        selected_label = st.selectbox(
            "Choose Person",
            [
                f"{row.full_name} — {row.position} — {row.card_id}"
                for row in current_members.itertuples()
            ],
            key="qr_person",
        )

        selected_card_id = selected_label.rsplit(" — ", 1)[-1]
        member = current_members[current_members["card_id"] == selected_card_id].iloc[0].to_dict()

        qr_img, profile_url = make_qr_image(member["id"])
        card_img = make_id_card(member)

        qcol, ccol = st.columns([1, 2])

        with qcol:
            st.markdown("#### QR Code")
            st.image(qr_img, width=280)
            st.code(profile_url)
            st.download_button(
                "Download QR PNG",
                data=image_to_png_bytes(qr_img),
                file_name=f"{member['card_id']}_QR.png",
                mime="image/png",
                use_container_width=True,
                key=f"qr_download_{member['id']}"
            )

        with ccol:
            st.markdown("#### Identity Card Preview")
            st.image(card_img, use_container_width=True)
            st.download_button(
                "Download ID Card PNG",
                data=image_to_png_bytes(card_img),
                file_name=f"{member['card_id']}_ID_Card.png",
                mime="image/png",
                use_container_width=True,
                key=f"card_download_{member['id']}"
            )

        st.caption(
            "For physical cards, you may either print the generated card or download the QR PNG "
            "and place it inside your official card design."
        )

# -----------------------------
# IMPORT / EXPORT
# -----------------------------
with tab4:
    st.subheader("Data Backup, Export and Bulk Import")

    export_df = get_all_members()

    if not export_df.empty:
        csv_bytes = export_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Complete Records CSV",
            data=csv_bytes,
            file_name="event_identity_records.csv",
            mime="text/csv",
            key="export_csv"
        )
    else:
        st.info("No records available to export.")

    st.divider()
    st.markdown("### Bulk Import CSV")
    st.write(
        "CSV columns supported: full_name, category, position, department, organization, "
        "email, phone, emergency_contact, blood_group, status, notes, card_id."
    )

    template = pd.DataFrame(
        [
            {
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
            }
        ]
    )

    st.download_button(
        "Download CSV Import Template",
        data=template.to_csv(index=False).encode("utf-8"),
        file_name="event_identity_import_template.csv",
        mime="text/csv",
        key="template_download"
    )

    uploaded = st.file_uploader("Upload Completed CSV", type=["csv"])

    if uploaded is not None:
        try:
            import_df = pd.read_csv(uploaded).fillna("")
            required_cols = {"full_name", "category", "position"}

            if not required_cols.issubset(import_df.columns):
                st.error("CSV must contain at least: full_name, category, position.")
            else:
                st.dataframe(import_df.head(20), use_container_width=True, hide_index=True)

                if st.button("Import Records", key="import_records_button"):
                    inserted = 0
                    skipped = 0

                    for _, row in import_df.iterrows():
                        full_name = str(row.get("full_name", "")).strip()
                        category = str(row.get("category", "Organizer")).strip() or "Organizer"
                        position = str(row.get("position", "")).strip()

                        if not full_name or not position:
                            skipped += 1
                            continue

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
                            "created_at": datetime.now().isoformat(timespec="seconds"),
                        }

                        try:
                            add_member(data)
                            inserted += 1
                        except sqlite3.IntegrityError:
                            skipped += 1

                    st.success(f"Import complete. Added: {inserted}. Skipped: {skipped}.")
                    st.rerun()

        except Exception as e:
            st.error(f"Could not read the CSV file: {e}")

st.divider()
st.caption(
    "Important: Streamlit Community Cloud does not guarantee permanent local-file persistence. "
    "For a live event system, use this version for development/testing or connect the database "
    "to a persistent service such as Supabase/PostgreSQL before relying on it as the sole source of records."
)
