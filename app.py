import streamlit as st
import pyodbc
import bcrypt
import re

# ---------------- DB CONNECTION ----------------
def get_connection():
    return pyodbc.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=DESKTOP-4BSV2BO\\SQLEXPRESS01;"
        "DATABASE=AuthDB;"
        "Trusted_Connection=yes;"
        "TrustServerCertificate=yes;"
    )

# ---------------- HELPERS ----------------
def strong_password(password):
    return re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', password)

# ---------------- REGISTER ----------------
def register_user(username, email, password):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT 1 FROM users WHERE username=? OR email=?",
        username, email
    )
    if cursor.fetchone():
        conn.close()
        return False, "Username or email already exists"

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    cursor.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        username, email, hashed_pw
    )
    conn.commit()
    conn.close()
    return True, "Signup successful"

# ---------------- LOGIN ----------------
def login_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash FROM users WHERE username=?",
        username
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    try:
        return bcrypt.checkpw(password.encode(), row[0].encode())
    except ValueError:
        return False

# ---------------- STREAMLIT UI ----------------
st.set_page_config(page_title="User Auth App", layout="centered")
st.title("🔐 User Authentication System")

menu = st.sidebar.selectbox("Menu", ["Signup", "Login", "Dashboard"])

# ---------------- SIGNUP ----------------
if menu == "Signup":
    st.subheader("Create Account")

    u = st.text_input("Username")
    e = st.text_input("Email")
    p = st.text_input("Password", type="password")
    rp = st.text_input("Confirm Password", type="password")

    if st.button("Signup"):
        if len(u) < 5:
            st.warning("Username must be at least 5 characters")
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", e):
            st.warning("Invalid email format")
        elif p != rp:
            st.warning("Passwords do not match")
        elif not strong_password(p):
            st.warning("Password must be strong")
        else:
            ok, msg = register_user(u, e, p)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

# ---------------- LOGIN ----------------
elif menu == "Login":
    st.subheader("Login")

    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        if login_user(u, p):
            st.session_state.user = u
            st.success("Login successful")
        else:
            st.error("Invalid credentials")

# ---------------- DASHBOARD ----------------
elif menu == "Dashboard":
    if "user" not in st.session_state:
        st.warning("Please login first")
    else:
        st.success(f"Welcome {st.session_state.user} 🎉")

        if st.button("Logout"):
            del st.session_state.user
            st.success("Logged out")
            