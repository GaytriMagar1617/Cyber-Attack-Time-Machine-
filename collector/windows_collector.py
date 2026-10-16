import subprocess
import json
import os
from datetime import datetime


def collect_windows_events():

    print("=" * 60)
    print("CYBER ATTACK TIME MACHINE")
    print("Windows Security Log Collector")
    print("=" * 60)

    command = [
        "powershell",
        "-Command",
        """
        Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=4624,4625,4688
        } -MaxEvents 20 |
        Select-Object TimeCreated, Id, ProviderName, Message |
        ConvertTo-Json -Depth 3
        """
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("Error while reading Windows Event Logs:")
            print(result.stderr)
            return

        if not result.stdout.strip():
            print("No matching Windows events found.")
            return

        events = json.loads(result.stdout)

        if isinstance(events, dict):
            events = [events]

        clean_events = []

        print("\nCollected Events:")
        print("-" * 60)

        for event in events:

            raw_time = event.get("TimeCreated")

            # Convert PowerShell JSON date
            if isinstance(raw_time, str) and raw_time.startswith("/Date("):

                milliseconds = int(
                    raw_time.replace("/Date(", "").replace(")/", "")
                )

                event_time = datetime.fromtimestamp(
                    milliseconds / 1000
                ).strftime("%Y-%m-%d %H:%M:%S")

            else:
                event_time = str(raw_time)

            event_id = event.get("Id")

            if event_id == 4624:
                event_type = "Successful Logon"

            elif event_id == 4625:
                event_type = "Failed Logon"

            elif event_id == 4688:
                event_type = "Process Creation"

            else:
                event_type = "Windows Security Event"

            clean_event = {
                "timestamp": event_time,
                "event_id": event_id,
                "event_type": event_type,
                "provider": event.get("ProviderName"),
                "message": event.get("Message")
            }

            clean_events.append(clean_event)

            print("Time:", event_time)
            print("Event ID:", event_id)
            print("Event Type:", event_type)
            print("-" * 60)

        # Create data folder
        project_folder = os.path.dirname(os.path.dirname(__file__))
        data_folder = os.path.join(project_folder, "data")

        os.makedirs(data_folder, exist_ok=True)

        # Save events to JSON
        output_file = os.path.join(data_folder, "events.json")

        with open(output_file, "w", encoding="utf-8") as file:

            json.dump(
                clean_events,
                file,
                indent=4,
                ensure_ascii=False
            )

        print()
        print("=" * 60)
        print("SUCCESS!")
        print(f"Saved {len(clean_events)} events.")
        print("File:", output_file)
        print("=" * 60)

    except Exception as error:

        print("Collector error:", error)


if __name__ == "__main__":
    collect_windows_events()