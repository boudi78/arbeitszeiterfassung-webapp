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
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/dbname")  # Use environment variable or default
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)

def add_user(username, email, password):
    db = SessionLocal()
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

def get_user(username):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    return user

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

init_db()

# ------------------------------
# Streamlit App: Navigation & Pages
# ------------------------------
if "page" not in st.session_state:
    st.session_state.page = "login"

def switch_page(page_name):
    st.session_state.page = page_name
    st.experimental_rerun()

# --- Authentication Pages ---
def login_page():
    # ... (No changes needed in login_page)

def signup_page():
    # ... (No changes needed in signup_page)

def forgot_password_page():
    # ... (No changes needed in forgot_password_page)


# ------------------------------
# Main Application Page (After Login)
# ------------------------------
def main_app():
    # ... (No changes in the core logic)

    # --- Data Editor and Related Changes ---
    search_name = st.text_input("🔍 Search Employee by Name")
    if search_name:
        mask = st.session_state.df['Mitarbeiter'].str.contains(search_name, case=False)
        filtered_df = st.session_state.df[mask]
    else:
        filtered_df = st.session_state.df

    # Key change: Refresh the dataframe after editing
    edited_df = st.data_editor(
        filtered_df,
        # ... (column_config remains the same)
        hide_index=True,
        use_container_width=True
    )

    if not edited_df.equals(filtered_df):  # Check if the DataFrame was actually modified
        st.session_state.df.update(edited_df)  # Directly update the main DataFrame
        st.session_state.df = calculate_hours(st.session_state.df)  # Recalculate hours
        st.experimental_rerun() # Rerun to reflect changes immediately


    # ... (Rest of the main_app function remains the same)


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
