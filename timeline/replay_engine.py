import json
import os
import time


# ---------------------------------------------------------
# Load timelines
# ---------------------------------------------------------

def load_timelines():

    project_folder = os.path.dirname(
        os.path.dirname(__file__)
    )

    data_folder = os.path.join(
        project_folder,
        "data"
    )

    input_file = os.path.join(
        data_folder,
        "timelines.json"
    )

    if not os.path.exists(input_file):

        print("ERROR: timelines.json not found.")

        return []

    with open(
        input_file,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ---------------------------------------------------------
# Replay one timeline
# ---------------------------------------------------------

def replay_timeline(timeline):

    print()
    print("=" * 60)
    print("CYBER ATTACK TIME MACHINE - REPLAY")
    print("=" * 60)

    print()
    print("Incident ID:",
          timeline["incident_id"])

    print("Incident Type:",
          timeline["incident_type"])

    print("Severity:",
          timeline["severity"])

    print("User:",
          timeline["user"])

    print("Source IP:",
          timeline["source_ip"])

    print()

    print("Starting attack timeline replay...")
    print("-" * 60)

    events = timeline.get(
        "events",
        []
    )

    for event in events:

        print()

        print(
            f'[{event["sequence"]}] '
            f'{event["timestamp"]}'
        )

        print(
            "Event:",
            event["event_type"]
        )

        print(
            "Event ID:",
            event["event_id"]
        )

        print(
            "User:",
            event["user"]
        )

        print(
            "Source IP:",
            event["source_ip"]
        )

        # Small delay to simulate replay
        time.sleep(1)

    print()
    print("-" * 60)

    print("REPLAY COMPLETE")

    print()
    print(
        "Incident:",
        timeline["incident_type"]
    )

    print(
        "Total Events:",
        len(events)
    )

    print("=" * 60)


# ---------------------------------------------------------
# Main function
# ---------------------------------------------------------

def run_replay_engine():

    timelines = load_timelines()

    if not timelines:

        print(
            "No timelines available for replay."
        )

        return

    print(
        f"Found {len(timelines)} timeline(s)."
    )

    # For now, replay the first incident
    replay_timeline(
        timelines[0]
    )


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":

    run_replay_engine()