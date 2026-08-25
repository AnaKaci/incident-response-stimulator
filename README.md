# Incident Response Simulator

Live demo: https://dafairva.github.io/incident-response-simulator/

Incident Response Simulator is a static, browser-based cybersecurity training platform. It turns an initial security signal into a realistic multi-role incident-response exercise where responders investigate telemetry, preserve evidence, build hypotheses, coordinate containment, remediate the issue, assess legal impact, and close the incident with a report.

## What's New

- Scenario selection screen with difficulty modes.
- Reusable scenario engine backed by JSON scenario definitions in `scenarios/`.
- Hidden ground truth separated from player knowledge.
- Mini SIEM with searchable synthetic telemetry and pivoting.
- Real SHA-256 evidence hashing using browser crypto.
- Chain-of-custody history for collected evidence.
- Incident hypothesis tracking with evidence-based confidence.
- Reactive attacker behavior that responds to defender actions.
- Asset state, service health, containment consequences, and incident tasks.
- Save/resume support through browser local storage.
- UI spacing polish for scenario, objective, AppSec, workspace, evidence, and checklist cards.

## Core Roles

- **SOC Analyst**: triage alerts, search telemetry, collect evidence, create hypotheses, identify IOCs, and escalate findings.
- **Incident Commander**: coordinate response, approve containment, track business impact, assign work, and authorize recovery.
- **AppSec Engineer**: reproduce the exploit safely, inspect code, build the remediation, test the fix, and request deployment.
- **Legal / Compliance**: assess facts, data classes, notification posture, communications, and legal rationale.

## Scenarios

The SQL Injection Data Exposure scenario is the current full reference implementation. Additional scenario definitions are included as authorable seeds:

- Ransomware / Active Directory Compromise
- Phishing / Account Takeover
- Business Email Compromise
- Cloud Credential Leak
- Insider Data Exfiltration
- Web Shell / Public Server Compromise
- Supply Chain Compromise

## Run Locally

Because the app loads JSON scenario files, serve it over local HTTP:

```bash
python -m http.server 8765 --bind 127.0.0.1
```

Then open:

```text
http://127.0.0.1:8765/index.html
```

No build step is required. The app is plain HTML, CSS, and JavaScript.

## GitHub Pages

This project is deployable directly from the repository root with GitHub Pages.

Live page:

```text
https://dafairva.github.io/incident-response-simulator/
```

## Project Structure

```text
index.html
styles.css
script.js
scenario-engine.js
lightning-background.js
roles/
scenarios/
```

## Development Notes

- Keep the existing SOC/cyber visual design intact.
- Prefer scoped CSS changes for UI polish.
- Keep scenario logic in scenario data and the scenario engine where possible.
- Do not expose `groundTruth` in responder-facing UI.
- Test role switching, SIEM queries, evidence collection, hypotheses, containment actions, save/resume, and report generation after significant edits.

