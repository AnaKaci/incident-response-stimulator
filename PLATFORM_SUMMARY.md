# Platform Summary

## Incident Response Simulator

Incident Response Simulator is a browser-based training platform that turns a security challenge signal into a realistic cybersecurity incident-response experience. Instead of ending at "flag found", the scenario continues into the real-world process of validating evidence, coordinating teams, remediating the issue, assessing compliance impact, and closing the incident properly.

## Main Roles

- **SOC Analyst**: investigates alerts, collects evidence, validates the incident, scopes exposure, and escalates confirmed findings.
- **Incident Commander**: coordinates the response, evaluates business impact, manages stakeholders, approves containment, and authorizes recovery.
- **AppSec Engineer**: reproduces the vulnerability safely, traces the root cause, applies a secure patch, runs tests, requests deployment, and verifies the fix.
- **Legal / Compliance**: assesses personal-data involvement, evaluates notification obligations, reviews communications, records legal rationale, and completes compliance closure.

## Core Simulation Flow

The platform follows an end-to-end incident journey:

```text
CTF signal -> SOC investigation -> Commander decision -> AppSec remediation
-> Legal assessment -> Recovery validation -> Final closure
```

Roles are always accessible, but incident information and actions are revealed progressively based on confirmed evidence and handoffs. This makes the simulator feel closer to a real incident-response environment instead of a simple linear dashboard.

## Key Features

- Role-specific workspaces and tools.
- Progressive disclosure of incident facts.
- Evidence collection and scoring.
- Realistic handoffs between teams.
- Approval workflow for containment and deployment.
- AI assistant behavior that depends on available evidence.
- Incident clock, metrics, live updates, and final debrief.
- Final report and post-incident review.

## Access

Live platform:

```text
https://dafairva.github.io/incident-response-simulator/
```

Source code:

```text
https://github.com/dafairva/incident-response-simulator
```
