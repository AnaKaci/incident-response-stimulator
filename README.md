# Incident Response Simulator

A static, interactive incident-response training simulator that turns a security challenge signal into a realistic multi-role response workflow.

## What It Includes

- SOC Analyst workspace for triage, investigation, evidence collection, and escalation.
- Incident Commander workspace for business impact, stakeholder coordination, decisions, approvals, and recovery authorization.
- AppSec Engineer workspace for exploit reproduction, code inspection, remediation, testing, deployment request, and fix validation.
- Legal / Compliance workspace for data classification, exposure assessment, notification decision, communications review, and compliance closure.
- End-to-end incident state, gated actions, progressive disclosure, live injects, final closure, scorecard, and post-incident review.

## Run Locally

Open this file in a browser:

```text
outputs/index.html
```

No build step is required. The simulator is a standalone HTML/CSS/JavaScript app.

## GitHub Pages

The root `index.html` redirects to `outputs/index.html`, so GitHub Pages can serve the project from the repository root.

## Collaboration Notes

- Main application file: `outputs/index.html`
- Keep changes focused and test the full role flow after editing.
- Avoid committing local screenshots, temporary files, or browser cache output.

