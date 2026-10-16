import json
import os
from datetime import datetime


# ---------------------------------------------------------
# Load events
# ---------------------------------------------------------

def load_events():

    project_folder = os.path.dirname(
        os.path.dirname(__file__)
    )

    data_folder = os.path.join(
        project_folder,
        "data"
    )

    input_file = os.path.join(
        data_folder,
        "normalized_events.json"
    )

    if not os.path.exists(input_file):

        print("ERROR: normalized_events.json not found.")

        return []

    with open(
        input_file,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ---------------------------------------------------------
# Convert timestamp to datetime
# ---------------------------------------------------------

def parse_timestamp(timestamp):

    try:

        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except (ValueError, TypeError):

        return None


# ---------------------------------------------------------
# Correlate failed login events
# ---------------------------------------------------------

def create_brute_force_incidents(events):

    incidents = []

    # Only failed login events
    failed_events = []

    for event in events:

        if event.get("event_id") == 4625:

            failed_events.append(event)

    # Group events by user + source IP
    groups = {}

    for event in failed_events:

        user = event.get("user")
        source_ip = event.get("source_ip")

        if not user:
            continue

        if not source_ip:
            continue

        key = (user, source_ip)

        if key not in groups:

            groups[key] = []

        groups[key].append(event)

    incident_number = 1

    # Analyze each group
    for (user, source_ip), user_events in groups.items():

        # Sort events chronologically
        user_events.sort(
            key=lambda event:
            parse_timestamp(
                event.get("timestamp")
            ) or datetime.min
        )

        # -------------------------------------------------
        # Time-based correlation
        # -------------------------------------------------

        correlated_events = []

        if user_events:

            first_time = parse_timestamp(
                user_events[0].get("timestamp")
            )

            if first_time:

                for event in user_events:

                    event_time = parse_timestamp(
                        event.get("timestamp")
                    )

                    if not event_time:
                        continue

                    time_difference = (
                        event_time - first_time
                    ).total_seconds()

                    # 5-minute correlation window
                    if time_difference <= 300:

                        correlated_events.append(event)

        # -------------------------------------------------
        # Incident threshold
        # -------------------------------------------------

        if len(correlated_events) >= 5:

            timestamps = []

            for event in correlated_events:

                timestamp = event.get(
                    "timestamp"
                )

                if timestamp:
                    timestamps.append(timestamp)

            timestamps.sort()

            incident = {

                "incident_id":
                    f"INC-{incident_number:04d}",

                "incident_type":
                    "Possible Brute Force Attack",

                "severity":
                    "high",

                "status":
                    "Open",

                "user":
                    user,

                "source_ip":
                    source_ip,

                "event_count":
                    len(correlated_events),

                "first_seen":
                    timestamps[0],

                "last_seen":
                    timestamps[-1],

                "correlation_window":
                    "5 minutes",

                "related_events":
                    correlated_events,

                "detection_rule":
                    "Possible Brute Force Attack"
            }

            incidents.append(incident)

            incident_number += 1

    return incidents


# ---------------------------------------------------------
# Run incident manager
# ---------------------------------------------------------

def run_incident_manager():

    print("=" * 60)
    print("CYBER ATTACK TIME MACHINE")
    print("INCIDENT CREATION & EVENT CORRELATION")
    print("=" * 60)

    events = load_events()

    if not events:

        print(
            "No events available for correlation."
        )

        return

    print()

    print(
        f"Analyzing {len(events)} events..."
    )

    print("-" * 60)

    incidents = create_brute_force_incidents(
        events
    )

    print()

    if not incidents:

        print(
            "No correlated security incidents created."
        )

    else:

        print("CORRELATED SECURITY INCIDENTS")

        print("-" * 60)

        for incident in incidents:

            print(
                "Incident ID:",
                incident["incident_id"]
            )

            print(
                "Type:",
                incident["incident_type"]
            )

            print(
                "Severity:",
                incident["severity"]
            )

            print(
                "Status:",
                incident["status"]
            )

            print(
                "User:",
                incident["user"]
            )

            print(
                "Source IP:",
                incident["source_ip"]
            )

            print(
                "Event Count:",
                incident["event_count"]
            )

            print(
                "First Seen:",
                incident["first_seen"]
            )

            print(
                "Last Seen:",
                incident["last_seen"]
            )

            print(
                "Correlation Window:",
                incident["correlation_window"]
            )

            print("-" * 60)

    # -----------------------------------------------------
    # Save incidents
    # -----------------------------------------------------

    project_folder = os.path.dirname(
        os.path.dirname(__file__)
    )

    data_folder = os.path.join(
        project_folder,
        "data"
    )

    output_file = os.path.join(
        data_folder,
        "incidents.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            incidents,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()

    print("=" * 60)

    print(
        f"Incident results saved to: {output_file}"
    )

    print("=" * 60)


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":

    run_incident_manager()