

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import os
import sqlite3
import bcrypt

# --- Datenbankfunktionen ---
DB_NAME = "users.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def add_user(username, email, password):
    conn = get_db_connection()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        st.success("Signup successful! You can now log in.")
    except sqlite3.IntegrityError:
        st.error("Username or email already exists.")
    finally:
        conn.close()

def get_user(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user

def update_password(username, new_password):
    conn = get_db_connection()
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
    conn.commit()
    conn.close()
    st.success("Password updated successfully!")

# --- Initialisiere die Datenbank ---
init_db()

# --- Seiten-Navigation für Auth ---
if "page" not in st.session_state:
    st.session_state.page = "login"  # Default page

def switch_page(page_name):
    st.session_state.page = page_name
    st.experimental_rerun()

# --- Login Seite ---
def login_page():
    st.title("🔐 WorkTime Pro+ Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    
    if st.button("Login"):
        user = get_user(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user["password_hash"]):
            st.success("✅ Login successful!")
            st.session_state.logged_in = True
            st.session_state.current_user = username
            switch_page("app")
        else:
            st.error("❌ Incorrect credentials")
    
    st.markdown("---")
    st.info("Don't have an account?")
    if st.button("Signup", key="to_signup"):
        switch_page("signup")
    st.markdown("---")
    if st.button("Forgot Password?", key="to_forgot"):
        switch_page("forgot_password")

# --- Signup Seite ---
def signup_page():
    st.title("📝 Signup")
    new_username = st.text_input("Choose a Username", key="signup_username")
    new_email = st.text_input("Your Email", key="signup_email")
    new_password = st.text_input("Choose a Password", type="password", key="signup_password")
    confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm_password")
    
    if st.button("Signup"):
        if new_password != confirm_password:
            st.error("Passwords do not match!")
        else:
            add_user(new_username, new_email, new_password)
    
    if st.button("Back to Login", key="back_to_login_from_signup"):
        switch_page("login")

# --- Forgot Password Seite ---
def forgot_password_page():
    st.title("🔑 Reset Password")
    username = st.text_input("Enter your Username", key="forgot_username")
    email = st.text_input("Enter your Registered Email", key="forgot_email")
    new_password = st.text_input("Enter New Password", type="password", key="forgot_new_password")
    confirm_new_password = st.text_input("Confirm New Password", type="password", key="forgot_confirm_new_password")
    
    if st.button("Reset Password"):
        user = get_user(username)
        if user and user["email"] == email:
            if new_password != confirm_new_password:
                st.error("Passwords do not match!")
            else:
                update_password(username, new_password)
                st.info("You can now log in with your new password.")
                switch_page("login")
        else:
            st.error("User not found or email does not match.")
    
    if st.button("Back to Login", key="back_to_login_from_forgot"):
        switch_page("login")

# --- Auth-Seiten Auswahl ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if st.session_state.page == "login":
    login_page()
elif st.session_state.page == "signup":
    signup_page()
elif st.session_state.page == "forgot_password":
    forgot_password_page()
elif st.session_state.page == "app" and not st.session_state.get("logged_in", False):
    # Falls der User noch nicht eingeloggt ist, zurück zur Login-Seite
    switch_page("login")

# --- Hauptanwendung (nach dem Login) ---
if st.session_state.get("logged_in", False) and st.session_state.page == "app":
    # Set page configuration (bereits oben gesetzt)
    st.title("⏱️ WorkTime Pro+ - Advanced Time Tracking")
    
    # --- Persistenz der Arbeitsplandaten ---
    SCHEDULE_FILE = "schedule.csv"
    
    def load_schedule():
        if os.path.exists(SCHEDULE_FILE):
            try:
                df = pd.read_csv(SCHEDULE_FILE, parse_dates=["Datum"])
                return df
            except Exception as e:
                st.error(f"Error loading schedule: {e}")
        return None
    
    def save_schedule(df):
        try:
            df.to_csv(SCHEDULE_FILE, index=False)
            st.success("Schedule saved!")
        except Exception as e:
            st.error(f"Error saving schedule: {e}")

    # --- Configuration und Funktionen ---
    STANDARD_HOURS = 8
    DEFAULT_HOURS = {"start": "08:00", "end": "17:00", "pause": 1.0}

    @st.cache_data
    def generate_schedule(start_date, end_date, workers):
        dates = pd.date_range(start_date, end_date)
        return pd.DataFrame([
            {
                "Datum": date.date(),
                "Mitarbeiter": worker,
                "Startzeit": datetime.strptime(DEFAULT_HOURS["start"], "%H:%M").time(),
                "Endzeit": datetime.strptime(DEFAULT_HOURS["end"], "%H:%M").time(),
                "Pause": DEFAULT_HOURS["pause"],
                "Krank": False,
                "Urlaub": False
            }
            for date in dates
            for worker in workers
        ])

    @st.cache_data
    def calculate_hours(df):
        try:
            df["Datum"] = pd.to_datetime(df["Datum"])
            df["Startzeit"] = pd.to_datetime(
                df["Datum"].astype(str) + " " + df["Startzeit"].astype(str),
                errors='coerce'
            )
            df["Endzeit"] = pd.to_datetime(
                df["Datum"].astype(str) + " " + df["Endzeit"].astype(str),
                errors='coerce'
            )

            # Berechnung der Arbeitszeit und Überstunden
            df["Arbeitszeit"] = (
                (df["Endzeit"] - df["Startzeit"]).dt.total_seconds() / 3600 - df["Pause"]
            )
            df["Überstunden"] = (df["Arbeitszeit"] - STANDARD_HOURS).clip(lower=0)

            # Falls Krank oder Urlaub, keine Arbeitszeit
            df["Arbeitszeit"] = df["Arbeitszeit"].where(~(df["Krank"] | df["Urlaub"]), 0)
            df["Überstunden"] = df["Überstunden"].where(~(df["Krank"] | df["Urlaub"]), 0)

            # Zusätzliche Spalten für Jahr, Quartal und Woche
            df["Woche"] = df["Datum"].dt.isocalendar().week
            df["Quartal"] = df["Datum"].dt.to_period('Q').astype(str)
            df["Jahr"] = df["Datum"].dt.year

            return df
        except Exception as e:
            st.error(f"Calculation error: {str(e)}")
            return df

    # Lade evtl. einen zuvor gespeicherten Plan
    if "df" not in st.session_state:
        loaded_df = load_schedule()
        if loaded_df is not None:
            st.session_state.df = loaded_df
        else:
            st.session_state.df = pd.DataFrame()  # Leere DataFrame

    # ===== Sidebar Controls =====
    with st.sidebar:
        st.header("Settings")
        worker_names = st.text_input(
            "🧑💼 Enter Worker Names (comma separated)",
            "Max Mustermann, Anna Müller, Tom Schneider"
        )
        selected_workers = [name.strip() for name in worker_names.split(",") if name.strip()]

        start_date = st.date_input("Start Date", datetime.today())
        end_date = st.date_input("End Date", datetime.today() + timedelta(days=7))

        if st.button("🔄 Generate Schedule"):
            if not selected_workers:
                st.error("Please enter worker names!")
            elif start_date > end_date:
                st.error("End date must be after start date!")
            else:
                with st.spinner("Generating..."):
                    try:
                        st.session_state.df = generate_schedule(start_date, end_date, selected_workers)
                        st.session_state.df = calculate_hours(st.session_state.df)
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

        if st.button("💾 Save Schedule"):
            if "df" in st.session_state and not st.session_state.df.empty:
                save_schedule(st.session_state.df)
            else:
                st.warning("No schedule to save!")

        if st.button("🚪 Logout"):
            st.session_state.clear()  # Alle session_state Variablen löschen
            st.experimental_rerun()  # App neu laden

    # ===== Main Interface =====
    if st.session_state.df.empty:
        st.info("👉 Generate schedule first using sidebar controls")
        st.stop()

    # Employee Search
    search_name = st.text_input("🔍 Search Employee by Name")
    if search_name:
        mask = st.session_state.df['Mitarbeiter'].str.contains(search_name, case=False)
        filtered_df = st.session_state.df[mask]
    else:
        filtered_df = st.session_state.df

    # Data Editor
    edited_df = st.data_editor(
        filtered_df,
        column_config={
            "Krank": st.column_config.CheckboxColumn("Sick"),
            "Urlaub": st.column_config.CheckboxColumn("Vacation"),
            "Startzeit": st.column_config.TimeColumn("Start"),
            "Endzeit": st.column_config.TimeColumn("End"),
            "Pause": st.column_config.NumberColumn("Break", format="%.1f"),
            "Überstunden": st.column_config.NumberColumn("Overtime", format="%.1f", disabled=True)
        },
        hide_index=True,
        use_container_width=True
    )

    # Update calculations
    if not edited_df.equals(filtered_df):
        st.session_state.df.update(edited_df)
        st.session_state.df = calculate_hours(st.session_state.df)
        st.experimental_rerun()

    # ===== Visualizations =====
    st.subheader("Analysis Dashboard")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Sick Days per Quarter")
        sick_days = st.session_state.df.groupby(["Mitarbeiter", "Quartal"])["Krank"].sum().reset_index()
        st.bar_chart(sick_days, x="Quartal", y="Krank", use_container_width=True)
    with col2:
        st.markdown("### Overtime Overview")
        overtime = st.session_state.df.groupby("Mitarbeiter")["Überstunden"].sum().reset_index()
        st.bar_chart(overtime, x="Mitarbeiter", y="Überstunden", use_container_width=True)

    # ===== Yearly Report =====
    st.divider()
    if st.button("📅 Generate Annual Report"):
        with st.spinner("Generating report..."):
            try:
                report = st.session_state.df.groupby(["Jahr", "Mitarbeiter"]).agg({
                    "Arbeitszeit": "sum",
                    "Überstunden": "sum",
                    "Krank": "sum",
                    "Urlaub": "sum"
                }).reset_index()

                with pd.ExcelWriter("annual_report.xlsx") as writer:
                    report.to_excel(writer, sheet_name="Summary", index=False)
                    st.session_state.df.to_excel(writer, sheet_name="Details", index=False)

                st.success("Report generated!")
                st.download_button(
                    "⬇️ Download Report",
                    data=open("annual_report.xlsx", "rb").read(),
                    file_name="annual_work_report.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
                st.dataframe(report)

            except Exception as e:
                st.error(f"Report error: {str(e)}")
