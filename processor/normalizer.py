import json
import os
import re


def extract_field(message, field_name):
    """
    Extract a field from a Windows event message.
    Example:
    Account Name: SYSTEM
    """

    if not message:
        return None

    pattern = rf"{re.escape(field_name)}:\s*(.+)"

    match = re.search(pattern, message)

    if match:
        return match.group(1).strip()

    return None


def normalize_event(event):

    event_id = event.get("event_id")
    message = event.get("message", "")

    # Default values
    user = None
    logon_type = None
    source_ip = None

    # Event ID 4624 = Successful Logon
    if event_id == 4624:

        user = extract_field(message, "Account Name")
        logon_type = extract_field(message, "Logon Type")
        source_ip = extract_field(message, "Source Network Address")

        severity = "low"

    # Event ID 4625 = Failed Logon
    elif event_id == 4625:

        user = extract_field(message, "Account Name")
        logon_type = extract_field(message, "Logon Type")
        source_ip = extract_field(message, "Source Network Address")

        severity = "medium"

    # Event ID 4688 = Process Creation
    elif event_id == 4688:

        user = extract_field(message, "Creator Subject: Account Name")
        severity = "medium"

    else:

        severity = "info"

    normalized_event = {
        "timestamp": event.get("timestamp"),
        "event_id": event_id,
        "event_type": event.get("event_type"),
        "user": user,
        "logon_type": logon_type,
        "source_ip": source_ip,
        "provider": event.get("provider"),
        "severity": severity
    }

    return normalized_event


def normalize_events():

    print("=" * 60)
    print("CYBER ATTACK TIME MACHINE")
    print("LOG NORMALIZATION")
    print("=" * 60)

    # Find project folder
    project_folder = os.path.dirname(
        os.path.dirname(__file__)
    )

    data_folder = os.path.join(
        project_folder,
        "data"
    )

    input_file = os.path.join(
        data_folder,
        "events.json"
    )

    output_file = os.path.join(
        data_folder,
        "normalized_events.json"
    )

    # Check input file
    if not os.path.exists(input_file):

        print("ERROR: events.json was not found.")
        print("Expected location:")
        print(input_file)

        return

    # Read events
    with open(
        input_file,
        "r",
        encoding="utf-8"
    ) as file:

        events = json.load(file)

    normalized_events = []

    print()
    print("Processing events...")
    print("-" * 60)

    for event in events:

        normalized_event = normalize_event(event)

        normalized_events.append(
            normalized_event
        )

        print(
            normalized_event["timestamp"],
            "|",
            normalized_event["event_id"],
            "|",
            normalized_event["event_type"]
        )

    # Save normalized events
    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized_events,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("-" * 60)
    print()
    print("SUCCESS!")
    print(
        f"Normalized {len(normalized_events)} events."
    )
    print()
    print("Output file:")
    print(output_file)
    print("=" * 60)


if __name__ == "__main__":
    normalize_events()