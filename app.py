import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt

# ------------------------------
# Database Setup with PostgreSQL
# ------------------------------
# The DATABASE_URL should be provided by Render as an environment variable.
# Format: postgresql://user:password@host:port/dbname
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/dbname")

# Create SQLAlchemy engine and session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define the User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables if they do not exist
def init_db():
    Base.metadata.create_all(bind=engine)

# Add a new user to the PostgreSQL database
def add_user(username, email, password):
    db = SessionLocal()
    # Hash the password and decode to store as a string
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=password_hash)
    try:
        db.add(new_user)
        db.commit()
        st.success("Signup successful! You can now log in.")
    except Exception as e:
        db.rollback()
        st.error(f"Error inserting user: {e}")
    finally:
        db.close()

# Retrieve a user by username
def get_user(username):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    return user

# Update a user's password
def update_password(username, new_password):
    db = SessionLocal()
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.password_hash = password_hash
            db.commit()
            st.success("Password updated successfully!")
        else:
            st.error("User not found.")
    except Exception as e:
        db.rollback()
        st.error(f"Error updating password: {e}")
    finally:
        db.close()

# Initialize the database on app start
init_db()

# ------------------------------
# Streamlit App: Navigation & Pages
# ------------------------------
if "page" not in st.session_state:
    st.session_state.page = "login"  # Default to login page

def switch_page(page_name):
    st.session_state.page = page_name
    st.experimental_rerun()

# --- Authentication Pages ---
def login_page():
    st.title("🔐 WorkTime Pro+ Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    
    if st.button("Login"):
        user = get_user(username)
        # Ensure stored password is compared as string
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
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

def forgot_password_page():
    st.title("🔑 Reset Password")
    username = st.text_input("Enter your Username", key="forgot_username")
    email = st.text_input("Enter your Registered Email", key="forgot_email")
    new_password = st.text_input("Enter New Password", type="password", key="forgot_new_password")
    confirm_new_password = st.text_input("Confirm New Password", type="password", key="forgot_confirm_new_password")
    
    if st.button("Reset Password"):
        user = get_user(username)
        # Access email from the SQLAlchemy model
        if user and user.email == email:
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

# ------------------------------
# Main Application Page (After Login)
# ------------------------------
def main_app():
    st.title("⏱️ WorkTime Pro+ - Advanced Time Tracking")
    
    # For demo purposes: using a CSV file to save the schedule.
    # (For production, you might use a separate persistent store.)
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
    
    # Schedule configuration
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
    
            df["Arbeitszeit"] = ((df["Endzeit"] - df["Startzeit"]).dt.total_seconds() / 3600) - df["Pause"]
            df["Überstunden"] = (df["Arbeitszeit"] - STANDARD_HOURS).clip(lower=0)
    
            df["Arbeitszeit"] = df["Arbeitszeit"].where(~(df["Krank"] | df["Urlaub"]), 0)
            df["Überstunden"] = df["Überstunden"].where(~(df["Krank"] | df["Urlaub"]), 0)
    
            df["Woche"] = df["Datum"].dt.isocalendar().week
            df["Quartal"] = df["Datum"].dt.to_period('Q').astype(str)
            df["Jahr"] = df["Datum"].dt.year
    
            return df
        except Exception as e:
            st.error(f"Calculation error: {e}")
            return df
    
    if "df" not in st.session_state:
        loaded_df = load_schedule()
        if loaded_df is not None:
            st.session_state.df = loaded_df
        else:
            st.session_state.df = pd.DataFrame()
    
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
                        st.error(f"Error: {e}")
    
        if st.button("💾 Save Schedule"):
            if "df" in st.session_state and not st.session_state.df.empty:
                save_schedule(st.session_state.df)
            else:
                st.warning("No schedule to save!")
    
        if st.button("🚪 Logout"):
            st.session_state.clear()
            st.experimental_rerun()
    
    if st.session_state.df.empty:
        st.info("👉 Generate schedule first using sidebar controls")
        st.stop()
    
    search_name = st.text_input("🔍 Search Employee by Name")
    if search_name:
        mask = st.session_state.df['Mitarbeiter'].str.contains(search_name, case=False)
        filtered_df = st.session_state.df[mask]
    else:
        filtered_df = st.session_state.df
    
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
    
    if not edited_df.equals(filtered_df):
        st.session_state.df.update(edited_df)
        st.session_state.df = calculate_hours(st.session_state.df)
        st.experimental_rerun()
    
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
                st.error(f"Report error: {e}")

# ------------------------------
# Page Routing Based on Session State
# ------------------------------
if st.session_state.page == "login":
    login_page()
elif st.session_state.page == "signup":
    signup_page()
elif st.session_state.page == "forgot_password":
    forgot_password_page()
elif st.session_state.page == "app":
    if st.session_state.get("logged_in", False):
        main_app()
    else:
        switch_page("login")
