import pandas as pd
from datetime import datetime, timedelta

def generate_schedule():
    start_date = datetime(2025, 1, 1)
    end_date = datetime(2025, 12, 31)
    dates = pd.date_range(start=start_date, end=end_date, freq='B')  # Nur Wochentage
    
    mitarbeiter = [f"Mitarbeiter {i}" for i in range(1, 11)]
    data = []
    
    for date in dates:
        for name in mitarbeiter:
            entry = [
                date.strftime("%Y-%m-%d"),
                date.strftime("%A"),
                name,
                "08:00",
                "17:00",
                60,
                "0",
                "0",
                "Nein",
                "Nein"
            ]
            data.append(entry)
    
    df = pd.DataFrame(data, columns=[
        "Datum", "Wochentag", "Name", "Startzeit", "Endzeit", "Pausenzeit (Min)",
        "Gesamtarbeitszeit (Std)", "Überstunden (Std)", "Krank", "Urlaub"
    ])
    return df

def berechne_arbeitszeiten(df):
    for index, row in df.iterrows():
        try:
            start_time = datetime.strptime(str(row["Startzeit"]), "%H:%M")
            end_time = datetime.strptime(str(row["Endzeit"]), "%H:%M")
            pause = int(row["Pausenzeit (Min)"])
            arbeitszeit = (end_time - start_time).seconds / 3600 - (pause / 60)
            df.at[index, "Gesamtarbeitszeit (Std)"] = round(arbeitszeit, 2)
            df.at[index, "Überstunden (Std)"] = max(round(arbeitszeit - 8, 2), 0)
        except Exception as e:
            print(f"Fehler in Zeile {index + 1}: {e}")
    return df

def speichern_excel(df, filename="Arbeitszeiterfassung_2025.xlsx"):
    df.to_excel(filename, index=False, engine='xlsxwriter')  # Verwende xlsxwriter als Alternative zu openpyxl
    print(f"Datei gespeichert: {filename}")

if __name__ == "__main__":
    df = generate_schedule()
    df = berechne_arbeitszeiten(df)
    speichern_excel(df)
