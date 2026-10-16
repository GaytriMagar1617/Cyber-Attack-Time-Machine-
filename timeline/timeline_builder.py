import json
import os
from datetime import datetime


# ---------------------------------------------------------
# Load incidents
# ---------------------------------------------------------

def load_incidents():

    project_folder = os.path.dirname(
        os.path.dirname(__file__)
    )

    data_folder = os.path.join(
        project_folder,
        "data"
    )

    input_file = os.path.join(
        data_folder,
        "incidents.json"
    )

    if not os.path.exists(input_file):

        print("ERROR: incidents.json not found.")

        return []

    with open(
        input_file,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ---------------------------------------------------------
# Build timeline for an incident
# ---------------------------------------------------------

def build_timeline(incident):

    timeline_events = []

    related_events = incident.get(
        "related_events",
        []
    )

    # Sort related events chronologically
    related_events.sort(
        key=lambda event:
        datetime.strptime(
            event.get("timestamp"),
            "%Y-%m-%d %H:%M:%S"
        )
    )

    for index, event in enumerate(
        related_events,
        start=1
    ):

        timeline_event = {

            "sequence": index,

            "timestamp":
                event.get("timestamp"),

            "event_id":
                event.get("event_id"),

            "event_type":
                event.get("event_type"),

            "user":
                event.get("user"),

            "source_ip":
                event.get("source_ip"),

            "severity":
                event.get("severity")
        }

        timeline_events.append(
            timeline_event
        )

    return timeline_events


# ---------------------------------------------------------
# Build all incident timelines
# ---------------------------------------------------------

def build_all_timelines(incidents):

    timelines = []

    for incident in incidents:

        timeline = {

            "incident_id":
                incident.get("incident_id"),

            "incident_type":
                incident.get("incident_type"),

            "severity":
                incident.get("severity"),

            "status":
                incident.get("status"),

            "user":
                incident.get("user"),

            "source_ip":
                incident.get("source_ip"),

            "first_seen":
                incident.get("first_seen"),

            "last_seen":
                incident.get("last_seen"),

            "event_count":
                incident.get("event_count"),

            "events":
                build_timeline(incident)
        }

        timelines.append(
            timeline
        )

    return timelines


# ---------------------------------------------------------
# Main function
# ---------------------------------------------------------

def run_timeline_builder():

    print("=" * 60)
    print("CYBER ATTACK TIME MACHINE")
    print("ATTACK TIMELINE RECONSTRUCTION")
    print("=" * 60)

    incidents = load_incidents()

    if not incidents:

        print()
        print("No incidents available.")

        return

    print()
    print(
        f"Processing {len(incidents)} incident(s)..."
    )

    print("-" * 60)

    timelines = build_all_timelines(
        incidents
    )

    # Display timelines
    for timeline in timelines:

        print()

        print(
            "Incident:",
            timeline["incident_id"]
        )

        print(
            "Type:",
            timeline["incident_type"]
        )

        print(
            "Severity:",
            timeline["severity"]
        )

        print(
            "User:",
            timeline["user"]
        )

        print(
            "Source IP:",
            timeline["source_ip"]
        )

        print()

        print("ATTACK TIMELINE")
        print("-" * 60)

        for event in timeline["events"]:

            print(
                f'{event["sequence"]}. '
                f'{event["timestamp"]} | '
                f'{event["event_type"]}'
            )

        print("-" * 60)

    # -----------------------------------------------------
    # Save timeline
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
        "timelines.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            timelines,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()

    print("=" * 60)

    print(
        f"Timeline saved to: {output_file}"
    )

    print("=" * 60)


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":

    run_timeline_builder()