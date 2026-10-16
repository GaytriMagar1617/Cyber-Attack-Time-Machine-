import json
import os
from collections import defaultdict
from datetime import datetime


# ---------------------------------------------------------
# Load normalized events
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
# Rule 1: Failed Login Detection
# ---------------------------------------------------------

def detect_failed_logins(events):

    findings = []

    failed_logins = []

    for event in events:

        if event.get("event_id") == 4625:

            failed_logins.append(event)

    if len(failed_logins) > 0:

        findings.append({
            "rule": "Failed Login Detection",
            "severity": "medium",
            "description": (
                f"{len(failed_logins)} failed login event(s) detected."
            ),
            "event_count": len(failed_logins)
        })

    return findings


# ---------------------------------------------------------
# Rule 2: Brute Force Detection
# ---------------------------------------------------------

def detect_brute_force(events):

    findings = []

    failures_by_user = defaultdict(list)

    for event in events:

        if event.get("event_id") == 4625:

            user = event.get("user")

            if user:
                failures_by_user[user].append(event)

    for user, failures in failures_by_user.items():

        if len(failures) >= 5:

            findings.append({
                "rule": "Possible Brute Force Attack",
                "severity": "high",
                "user": user,
                "event_count": len(failures),
                "description": (
                    f"{len(failures)} failed logons detected "
                    f"for user '{user}'."
                )
            })

    return findings


# ---------------------------------------------------------
# Rule 3: Process Creation Detection
# ---------------------------------------------------------

def detect_process_creation(events):

    findings = []

    process_events = []

    for event in events:

        if event.get("event_id") == 4688:

            process_events.append(event)

    if len(process_events) > 0:

        findings.append({
            "rule": "Process Creation Activity",
            "severity": "medium",
            "event_count": len(process_events),
            "description": (
                f"{len(process_events)} process creation "
                "event(s) detected."
            )
        })

    return findings


# ---------------------------------------------------------
# Run all detection rules
# ---------------------------------------------------------

def run_detection():

    print("=" * 60)
    print("CYBER ATTACK TIME MACHINE")
    print("DETECTION ENGINE")
    print("=" * 60)

    events = load_events()

    if not events:

        print("No events available for detection.")

        return

    print()
    print(f"Analyzing {len(events)} normalized events...")
    print("-" * 60)

    findings = []

    findings.extend(
        detect_failed_logins(events)
    )

    findings.extend(
        detect_brute_force(events)
    )

    findings.extend(
        detect_process_creation(events)
    )

    # -----------------------------------------------------
    # Display results
    # -----------------------------------------------------

    print()

    if not findings:

        print("No suspicious activity detected.")

    else:

        print("SECURITY FINDINGS")
        print("-" * 60)

        for finding in findings:

            print(
                "Rule:",
                finding["rule"]
            )

            print(
                "Severity:",
                finding["severity"]
            )

            print(
                "Description:",
                finding["description"]
            )

            print("-" * 60)

    # -----------------------------------------------------
    # Save detection results
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
        "detections.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            findings,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print("=" * 60)
    print(
        f"Detection results saved to: {output_file}"
    )
    print("=" * 60)


if __name__ == "__main__":
    run_detection()