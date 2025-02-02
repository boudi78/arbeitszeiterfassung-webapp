import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import os

# Set page configuration FIRST (must be at the very top)
st.set_page_config(page_title="WorkTime Pro+", layout="wide", page_icon="⏱️")

# --- Secure Login ---
def login():
    st.title("🔐 WorkTime Pro+ Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    # Fetch credentials from environment variables (or defaults)
    correct_username = os.getenv("APP_USERNAME", "Teamsped")  # Default username
    correct_password = os.getenv("APP_PASSWORD", "Beirut1578.")  # Default password

    if username == correct_username and password == correct_password:
        st.success("✅ Login successful!")
        st.session_state.logged_in = True  # Set logged_in to True
        return True
    elif username and password:
        st.error("❌ Incorrect credentials")
    return False

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:  # Show login form if not logged in
    if not login():
        st.stop()  # Stop execution if login fails

# --- Configuration ---
STANDARD_HOURS = 8
DEFAULT_HOURS = {"start": "08:00", "end": "17:00", "pause": 1.0}

# --- Cached Functions ---
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

        # Calculate Arbeitszeit and Überstunden
        df["Arbeitszeit"] = (
            (df["Endzeit"] - df["Startzeit"]).dt.total_seconds() / 3600 - df["Pause"]
        )
        df["Überstunden"] = (df["Arbeitszeit"] - STANDARD_HOURS).clip(lower=0)

        # Handle Krank and Urlaub
        df["Arbeitszeit"] = df["Arbeitszeit"].where(~(df["Krank"] | df["Urlaub"]), 0)
        df["Überstunden"] = df["Überstunden"].where(~(df["Krank"] | df["Urlaub"]), 0)

        # Add additional columns for the year, quarter, and week
        df["Woche"] = df["Datum"].dt.isocalendar().week
        df["Quartal"] = df["Datum"].dt.to_period('Q').astype(str)
        df["Jahr"] = df["Datum"].dt.year

        return df
    except Exception as e:
        st.error(f"Calculation error: {str(e)}")
        return df

# --- Streamlit App ---
st.title("⏱️ WorkTime Pro+ - Advanced Time Tracking")

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

    if st.button("🚪 Logout"):
        st.session_state.clear()  # Clear ALL session state variables
        st.session_state["logged_in"] = False  # Explicitly set logged_in to False
        st.experimental_rerun()  # Force Streamlit to rerun the script

# ===== Main Interface =====
if "df" not in st.session_state or st.session_state.df.empty:
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
    st.rerun()

# ===== Visualizations =====
st.subheader("Analysis Dashboard")

col1, col2 = st.columns(2)
with col1:
    st.markdown("### Sick Days per Quarter")
    sick_days = st.session_state.df.groupby(["Mitarbeiter", "Quartal"])["Krank"].sum().reset_index()
    st.bar_chart(sick_days, x="Quartal", y="Krank", color="Mitarbeiter")

with col2:
    st.markdown("### Overtime Overview")
    overtime = st.session_state.df.groupby("Mitarbeiter")["Überstunden"].sum().reset_index()
    st.bar_chart(overtime, x="Mitarbeiter", y="Überstunden", color="Mitarbeiter")

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

