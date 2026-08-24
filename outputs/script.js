const phases = [
      {
        time: "09:12",
        title: "The flag is real. Is this a bug or an incident?",
        tags: ["Detection", "Triage", "CTF → SOC"],
        map: "SQLi traffic is probing the portal.",
        terminal: "flag{union_select_customer_dump}\nGET /customers?id=12 UNION SELECT email,password_hash FROM users--",
        mini: "$ socctl create-incident --severity high\nincident_id=INC-2026-0812\nowner=SOC-L2\nstatus=triage",
        story: "You found a SQL Injection in the customer portal. In the CTF, that proves the exploit. In a real company, the same payload means an attacker may have queried customer data before you arrived. Your first decision determines whether this is handled as a controlled incident or an ignored vulnerability.",
        translation: "The technical flag becomes an indicator of compromise. The real question is not only 'can we patch it?' but 'has it already been exploited?'.",
        feed: [
          { time: "09:12", title: "WAF alert", summary: "UNION SELECT pattern on /customers?id=", source: "Edge WAF", severity: "High", impact: "Active exploit traffic is reaching the portal.", response: "Switch SQLi rule from monitor to block after confirming false-positive risk.", detail: "The payload matches the same technique used to retrieve the CTF flag. In production this is treated as a live exploitation signal." },
          { time: "09:13", title: "Database anomaly", summary: "users table reads are 8x above baseline", source: "DB audit", severity: "High", impact: "Sensitive rows may have been enumerated.", response: "Preserve query logs, identify affected fields, and correlate with web requests.", detail: "A normal customer profile request should not scan tens of thousands of rows from the users table." },
          { time: "09:14", title: "Support ticket", summary: "Two customers report unexpected profile data", source: "Customer Support", severity: "Medium", impact: "Possible data mix-up or unauthorized reads.", response: "Link customer reports to request IDs and preserve affected account records.", detail: "Business reports are often the clue that a technical exploit has visible customer impact." }
        ],
        evidence: {
          "HTTP logs": {
            explain: "These requests connect the CTF payload to real traffic hitting production.",
            log: "09:10:21 198.51.100.24 GET /customers?id=12\n09:10:28 198.51.100.24 GET /customers?id=12 UNION SELECT email,password_hash FROM users--\n09:11:02 198.51.100.24 GET /customers?id=12 UNION SELECT card_last4,phone FROM customers--"
          },
          "Database": {
            explain: "The database behavior shows this was not just a harmless scan.",
            log: "query: SELECT email,password_hash FROM users WHERE customer_id IN impacted_session_scope\nrecords accessed: 247\nrole: web_portal_ro"
          },
          "Business impact": {
            explain: "Real incidents connect technical exploitation to customers, law, reputation, and downtime.",
            log: "system: Customer Portal\ndata classes: email, phone, password_hash, subscription plan\npossible obligations: legal review, customer notification, regulator timeline"
          }
        },
        choices: [
          { label: "Notify SOC and open an incident", desc: "Create a high-severity ticket, preserve indicators, and assign an owner.", tone: "good", outcome: "Strong move. The issue gets ownership, evidence starts being preserved, and no one treats it as a normal bug ticket.", score: 30, risk: -12, evidence: 18, loss: 8000 },
          { label: "Patch immediately without triage", desc: "Fix the query as fast as possible and move on.", tone: "warn", outcome: "The patch helps, but you lose context. If data was queried before the patch, the company still needs to know.", score: 8, risk: -4, evidence: -10, loss: 65000 },
          { label: "Ignore it as a lab finding", desc: "Assume it only matters inside the CTF environment.", tone: "bad", outcome: "The attacker keeps testing the endpoint. A technical alert becomes a customer-data breach.", score: -25, risk: 24, evidence: -8, loss: 280000 },
          { label: "Preserve evidence first", desc: "Export logs, payloads, database traces, and timestamps before changes.", tone: "good", outcome: "Evidence quality improves. The team can now separate your test from attacker activity.", score: 24, risk: -6, evidence: 28, loss: 12000 }
        ]
      },
      {
        time: "09:27",
        title: "Scope the damage before guessing",
        tags: ["Evidence", "Scope", "Forensics"],
        map: "The database path is under investigation.",
        terminal: "$ siem search src_ip=198.51.100.24 earliest=-30d\nmatches=37\nrelated_rules=WAF-1192,DB-8841,IAM-2210",
        mini: "$ db-audit summarize --table users\nrows_accessed=247\nexternal_exfiltration=not_established\nconfidence=medium-high",
        story: "SOC confirms suspicious traffic before your CTF discovery. Now you must determine what happened: which tables were queried, whether credentials were reused, and whether the attacker moved beyond the web app.",
        translation: "A CTF validates exploitation. A real-world investigation validates scope: what was accessed, by whom, when, and with what business impact.",
        feed: [
          { time: "09:22", title: "SIEM correlation", summary: "Same IP attempted /admin/export before SQLi", source: "SIEM", severity: "High", impact: "The actor may have attempted bulk export before exploiting SQLi.", response: "Search the IP, user-agent, and session IDs across 30 days.", detail: "Correlation turns isolated alerts into a timeline: reconnaissance, exploitation, then possible data access." },
          { time: "09:25", title: "IAM alert", summary: "web_portal_ro used from an unusual execution path", source: "Identity logs", severity: "Medium", impact: "The service role may be abused beyond expected application flow.", response: "Rotate the credential and restrict the role while preserving authentication logs.", detail: "Read-only credentials can still cause a breach if they expose sensitive tables." },
          { time: "09:27", title: "Legal message", summary: "Do we have confirmed customer data exposure?", source: "Legal", severity: "Medium", impact: "Notification obligations depend on evidence-backed scope.", response: "Separate confirmed, likely, and unknown facts in the incident record.", detail: "Legal does not need panic. Legal needs facts, timestamps, affected data classes, and confidence levels." }
        ],
        evidence: {
          "SIEM": {
            explain: "Correlation turns separate events into an incident story.",
            log: "rule: Web exploit followed by sensitive table scan\nsource: 198.51.100.24\nconfidence: high\nrelated events: WAF-1192, DB-8841, IAM-2210"
          },
          "Accounts": {
            explain: "Account review checks whether the attacker reused credentials or tokens.",
            log: "web_portal_ro: read-only, no MFA, password rotated 120 days ago\nadmin_exporter: 14 failed login attempts\ncustomer_support_api: no suspicious use"
          },
          "Customer scope": {
            explain: "Scope is the basis for legal, customer, and executive decisions.",
            log: "confirmed records accessed: 247\nexternal exfiltration: not established\nsensitive fields: name, email, password_hash\npayment data: not stored in portal database"
          }
        },
        choices: [
          { label: "Search IoCs across SIEM and DB", desc: "Hunt for IP, payload, query pattern, user-agent, and time window.", tone: "good", outcome: "You discover the attack started two hours before the flag. Scope becomes defensible instead of guessed.", score: 32, risk: -10, evidence: 24, loss: 18000 },
          { label: "Delete your test logs", desc: "Remove your CTF activity so it does not confuse the investigation.", tone: "bad", outcome: "Chain of custody is damaged. The team can no longer cleanly separate testing from attacker actions.", score: -35, risk: 15, evidence: -35, loss: 360000 },
          { label: "Ask only the developer", desc: "Rely on the memory of the person who built the feature.", tone: "warn", outcome: "Developer context helps, but memory is not evidence. Scope remains incomplete.", score: 6, risk: 6, evidence: 4, loss: 90000 },
          { label: "Rotate the service account", desc: "Change database credentials and restrict the web role.", tone: "good", outcome: "The attacker loses a likely replay path and future database access becomes harder.", score: 26, risk: -14, evidence: 8, loss: 16000 }
        ]
      },
      {
        time: "09:45",
        title: "Contain the attack without breaking the business",
        tags: ["Containment", "Patch", "Business"],
        map: "Containment controls are moving between WAF, app, and database.",
        terminal: "$ waf rule enable SQLI-CUSTOMERS-ENDPOINT --mode block\nstatus=blocking\nfalse_positive_estimate=low",
        mini: "$ deploy patch customer-portal#4821\nchange=parameterized_query\nhealth=monitoring",
        story: "The portal is active and customers are online. Leaving the exploit open increases damage, but taking everything offline creates business loss. You need containment that reduces risk while preserving evidence and service.",
        translation: "Patching is only one part. Real containment balances exploit blocking, evidence preservation, uptime, testing, and communication.",
        feed: [
          { time: "09:38", title: "Traffic spike", summary: "Repeated SQLi payloads are still reaching monitor-mode WAF", source: "WAF telemetry", severity: "High", impact: "The attacker is still active while the exploit remains reachable.", response: "Enable blocking for this endpoint and monitor false positives.", detail: "Monitor mode is useful for learning. During active exploitation, it must become enforcement." },
          { time: "09:41", title: "Business owner", summary: "Customer portal should stay online if possible", source: "Product owner", severity: "Medium", impact: "Downtime creates customer and revenue impact.", response: "Prefer targeted containment over full shutdown when technically safe.", detail: "Security decisions are also business decisions. The best response reduces risk without unnecessary outage." },
          { time: "09:45", title: "Dev team", summary: "Parameterized query patch is ready for review", source: "Engineering", severity: "Low", impact: "Permanent remediation is available.", response: "Review, test, deploy, and monitor application health.", detail: "A WAF can buy time. The application patch removes the root cause." }
        ],
        evidence: {
          "Patch diff": {
            explain: "This is the core technical fix: stop building SQL with string concatenation.",
            log: "- query = \"SELECT * FROM customers WHERE id = \" + req.query.id\n+ query = \"SELECT * FROM customers WHERE id = ?\"\n+ db.execute(query, [req.query.id])"
          },
          "WAF": {
            explain: "WAF blocking can reduce immediate risk while the application patch is deployed.",
            log: "candidate rule: block UNION SELECT, information_schema, stacked queries\nmode: monitor -> block\nexpected false positives: low for /customers endpoint"
          },
          "Downtime": {
            explain: "Security decisions directly affect revenue and customer trust.",
            log: "portal users online: 1,284\nestimated revenue impact if offline: €4,500/hour\ncurrent risk if online without block: high"
          }
        },
        choices: [
          { label: "Enable WAF block and deploy tested patch", desc: "Block active payloads, deploy the parameterized query patch, and monitor errors.", tone: "good", outcome: "The exploit path is blocked quickly and the real fix lands with control. This is practical containment.", score: 34, risk: -22, evidence: 6, loss: 22000 },
          { label: "Take the portal offline silently", desc: "Shut everything down without support, legal, or business coordination.", tone: "warn", outcome: "The attack stops, but the business and support teams are surprised. Technical containment creates avoidable chaos.", score: 2, risk: -12, evidence: 2, loss: 140000 },
          { label: "Wait for tomorrow's maintenance window", desc: "Keep the system open until the normal deployment time.", tone: "bad", outcome: "The attacker gets more time. Maintenance windows do not matter when there is active exploitation.", score: -32, risk: 28, evidence: -4, loss: 520000 },
          { label: "Deploy the patch without testing", desc: "Push directly to production as fast as possible.", tone: "warn", outcome: "The vulnerability closes, but checkout errors spike and support volume increases.", score: 8, risk: -8, evidence: 0, loss: 110000 }
        ]
      },
      {
        time: "10:20",
        title: "Close the incident with a real report",
        tags: ["Legal", "Recovery", "Lessons"],
        map: "The incident moves from containment to recovery and reporting.",
        terminal: "$ incident report generate INC-2026-0812\nsections=timeline,scope,impact,actions,lessons\nstatus=draft_ready",
        mini: "$ runbook create web-exploit-response\nowners=SOC,AppSec,Legal,Engineering\nreview=scheduled",
        story: "The exploit path is controlled. Now the company needs a clear record: what happened, what data may have been touched, what actions were taken, and what changes prevent the same weakness from returning.",
        translation: "A real incident does not end with a flag or a patch. It ends with evidence-backed reporting, ownership, lessons learned, and durable fixes.",
        feed: [
          { time: "10:02", title: "SOC update", summary: "No SQLi payloads passed after WAF block", source: "SOC", severity: "Low", impact: "Containment appears effective.", response: "Continue monitoring and validate patch telemetry.", detail: "Good containment is measured, not assumed. Watch both security and application health signals." },
          { time: "10:11", title: "Legal request", summary: "Need written scope and evidence summary", source: "Legal", severity: "Medium", impact: "External communication may depend on the report.", response: "Deliver confirmed facts, likely exposure, unknowns, and next update time.", detail: "A precise report prevents both under-reporting and unnecessary alarm." },
          { time: "10:20", title: "CTO request", summary: "Prepare post-incident actions for board update", source: "Executive", severity: "Medium", impact: "Leadership needs risk reduction, not just technical detail.", response: "Translate the incident into control improvements and owners.", detail: "The board cares about customer risk, business exposure, and whether the same incident can happen again." }
        ],
        evidence: {
          "Timeline": {
            explain: "A clean timeline makes the incident understandable for technical and non-technical stakeholders.",
            log: "09:10 first suspicious SQLi request\n09:12 CTF flag confirms exploitable SQLi\n09:18 SOC ticket opened\n09:31 scope search started\n09:47 WAF block enabled\n10:02 patch deployed and monitored"
          },
          "Report": {
            explain: "The report separates confirmed facts from assumptions.",
            log: "confirmed: SQL Injection existed and was exploited for table scans\nlikely: customer contact data was queried\nnot confirmed: payment data exposure\nactions: SOC escalation, evidence preservation, credential rotation, WAF block, parameterized query patch"
          },
          "Hardening": {
            explain: "This is where a CTF lesson becomes a permanent security improvement.",
            log: "add SAST check for SQLi\nrequire parameterized queries\nrotate DB credentials every 60 days\ncreate runbook: Web exploit -> Incident response\nrun tabletop exercise for SOC + Dev"
          }
        },
        choices: [
          { label: "Write an evidence-backed report", desc: "Include timeline, scope, decisions, business impact, and follow-up actions.", tone: "good", outcome: "The incident closes professionally. Leadership understands the risk and the team has clear next steps.", score: 32, risk: -10, evidence: 10, loss: 10000 },
          { label: "Say only 'it was patched'", desc: "Close the ticket with minimal notes and no scope explanation.", tone: "bad", outcome: "The bug is closed, but the organization did not learn. Audit and legal questions remain unanswered.", score: -20, risk: 12, evidence: -8, loss: 180000 },
          { label: "Blame the developer", desc: "Frame it as a personal mistake instead of a process failure.", tone: "bad", outcome: "Reporting culture gets worse. Next time, people may hide problems instead of escalating them.", score: -24, risk: 18, evidence: 0, loss: 220000 },
          { label: "Create a web-exploit runbook", desc: "Document escalation, evidence, containment, patching, and communication steps.", tone: "good", outcome: "Future response becomes faster, clearer, and less dependent on one person remembering the process.", score: 26, risk: -12, evidence: 8, loss: 14000 }
        ]
      }
    ];

    const state = {
      phase: 0,
      selected: false,
      activeTab: "",
      activeEvent: 0,
      visualView: "attack",
      selectedNode: null,
      selectedKillStep: 0,
      checks: {},
      appliedRecs: {},
      loggedIn: false,
      selectedLoginRole: null,
      user: null,
      role: "SOC Analyst",
      wafAlertOpened: false,
      answeredMessages: {},
      selectedEvidence: {},
      collectedEvidence: {},
      selectedKillEvent: null,
      killAssignments: {},
      approvals: [],
      patchTested: false,
      patchDeployed: false,
      legalAnswer: "",
      selectedInbox: "",
      inboxStatuses: {},
      selectedEvidenceRow: null,
      objectiveStep: 0,
      pendingMetricDelta: {},
      reportReadiness: 0,
      attackerProgress: 0,
      stageIndex: 0,
      attackerHold: 0,
      paused: false,
      demoSpeed: 1,
      serviceHealth: 100,
      detectedTime: null,
      containmentTime: null,
      evidenceFilter: "all",
      highlightEvidenceId: null,
      elapsedSeconds: 0,
      recordsExposed: null,
      incidentClock: {
        detectedAt: null,
        acknowledgedAt: null,
        escalatedAt: null,
        containedAt: null,
        recoveredAt: null,
        closedAt: null
      },
      handoffs: {
        commander: { version: 0, updatedAt: null, summary: "No SOC handoff yet." },
        appsec: { version: 0, updatedAt: null, summary: "No remediation handoff yet." },
        legal: { version: 0, updatedAt: null, summary: "No legal handoff yet." }
      },
      handoffViews: { commander: 0, appsec: 0, legal: 0 },
      injectsSeen: {},
      supportComplaints: 0,
      monitoringStableSince: null,
      recoveryAuthorized: false,
      terminalLines: ["SOC TERMINAL READY", "type 'help' to list commands"],
      liveTick: 0,
      score: 0,
      risk: 44,
      evidence: 0,
      loss: 0,
      history: [],
      actionTimeline: [
        { time: "09:12", actor: "System", action: "WAF alert received for customer-portal-prod" }
      ],
      evidenceNotes: {}
      ,
      commanderAccepted: false,
      commandDecision: null,
      commandComms: {}
      ,
      commanderSlaBreached: false,
      appsecHandoffAccepted: false,
      appsecBaselineRun: false,
      appsecExploitReproduced: false,
      appsecTraceInspected: false,
      appsecRootCauseConfirmed: false,
      appsecSelectedPatch: "parameterized",
      appsecPatchApplied: false,
      appsecDeploymentRequested: false,
      legalHandoffAccepted: false,
      legalDataClasses: {},
      legalExposureSaved: false,
      legalBreachStatus: "PENDING",
      legalRiskLevel: "PENDING",
      legalAuthorityNotification: "PENDING",
      legalSubjectNotification: "PENDING",
      legalRationale: "",
      legalDecisionRecorded: false,
      legalClockStartedAt: null,
      legalComms: {}
    };

    function hydrateRolePartials() {
      const partials = window.SimulatorRolePartials || {};
      document.querySelectorAll("[data-role-partial]").forEach(slot => {
        const [role, section] = (slot.dataset.rolePartial || "").split(":");
        const html = partials[role]?.[section];
        if (typeof html !== "string") {
          slot.remove();
          return;
        }
        const template = document.createElement("template");
        template.innerHTML = html.trim();
        slot.replaceWith(template.content.cloneNode(true));
      });
    }

    hydrateRolePartials();

    const $ = id => document.getElementById(id);
    const els = {
      clock: $("clock"),
      phaseTitle: $("phaseTitle"),
      phaseTags: $("phaseTags"),
      story: $("story"),
      choices: $("choices"),
      outcome: $("outcome"),
      feed: $("feed"),
      tabs: $("tabs"),
      evidenceExplain: $("evidenceExplain"),
      evidenceLog: $("evidenceLog"),
      translation: $("translation"),
      phases: $("phases"),
      inboxNavBtn: $("inboxNavBtn"),
      commandMetrics: $("commandMetrics"),
      next: $("next"),
      finish: $("finish"),
      restart: $("restart"),
      report: $("report"),
      loginPanel: $("loginPanel"),
      score: $("score"),
      attackerProgressMetric: $("attackerProgressMetric"),
      risk: $("risk"),
      evidence: $("evidence"),
      loss: $("loss"),
      assetsAffected: $("assetsAffected"),
      recordsExposed: $("recordsExposed"),
      scoreBar: $("scoreBar"),
      riskBar: $("riskBar"),
      evidenceBar: $("evidenceBar"),
      lossBar: $("lossBar"),
      assetsBar: $("assetsBar"),
      recordsBar: $("recordsBar"),
      mttdMetric: $("mttdMetric"),
      mttcMetric: $("mttcMetric"),
      serviceHealthMetric: $("serviceHealthMetric"),
      mttdBar: $("mttdBar"),
      mttcBar: $("mttcBar"),
      serviceHealthBar: $("serviceHealthBar"),
      incidentTimer: $("incidentTimer"),
      attackerStage: $("attackerStage"),
      socTerminalOutput: $("socTerminalOutput"),
      socCommandInput: $("socCommandInput"),
      socCommandRun: $("socCommandRun"),
      objectiveTitle: $("objectiveTitle"),
      objectiveText: $("objectiveText"),
      objectiveActions: $("objectiveActions"),
      ctfToggle: $("ctfToggle"),
      evidenceLogRows: $("evidenceLogRows"),
      eventInspector: $("eventInspector"),
      collectedEvidenceList: $("collectedEvidenceList"),
      toastStack: $("toastStack"),
      mapCaption: $("mapCaption"),
      attackBadge: $("attackBadge"),
      flagTerminal: $("flagTerminal"),
      miniTerminal: $("miniTerminal"),
      eventDetail: $("eventDetail"),
      investigationGrid: $("investigationGrid"),
      investigationNote: $("investigationNote"),
      briefingGrid: $("briefingGrid"),
      flowStrip: $("flowStrip"),
      statusLights: $("statusLights"),
      impactHeat: $("impactHeat"),
      aiAnswer: $("aiAnswer"),
      promptRow: $("promptRow"),
      recommendations: $("recommendations"),
      tickerTrack: $("tickerTrack"),
      aiStream: $("aiStream"),
      confidenceRows: $("confidenceRows"),
      evidenceTimeline: $("evidenceTimeline"),
      evidenceTimelineTitle: $("evidenceTimelineTitle"),
      evidenceGameTitle: $("evidenceGameTitle"),
      evidenceGameIntro: $("evidenceGameIntro"),
      killLabDetail: $("killLabDetail"),
      killSimText: $("killSimText"),
      phaseRealScene: $("phaseRealScene"),
      phaseVisualTitle: $("phaseVisualTitle"),
      phaseVisualMetric: $("phaseVisualMetric"),
      livePacket: $("livePacket"),
      liveSiem: $("liveSiem"),
      liveDb: $("liveDb"),
      liveResponder: $("liveResponder"),
      livePacketLabel: $("livePacketLabel"),
      liveSiemLabel: $("liveSiemLabel"),
      liveDbLabel: $("liveDbLabel"),
      liveResponderLabel: $("liveResponderLabel"),
      roleGrid: $("roleGrid"),
      roleBrief: $("roleBrief"),
      commsGrid: $("commsGrid"),
      evidencePicker: $("evidencePicker"),
      reportPreview: $("reportPreview"),
      generatedReport: $("generatedReport"),
      generateReportBtn: $("generateReportBtn"),
      closeIncidentBtn: $("closeIncidentBtn"),
      socInbox: $("socInbox"),
      warRoomNavBtn: $("warRoomNavBtn"),
      reportBuilderNavBtn: $("reportBuilderNavBtn"),
      aiPanelTitle: $("aiPanelTitle"),
      reportBuilderTitle: $("reportBuilderTitle"),
      reportBuilderIntro: $("reportBuilderIntro"),
      inboxTitle: $("inboxTitle"),
      inboxIntro: $("inboxIntro"),
      killGameEvents: $("killGameEvents"),
      killGameBuckets: $("killGameBuckets"),
      killGameStatus: $("killGameStatus"),
      appsecCode: $("appsecCode"),
      appsecTests: $("appsecTests"),
      appsecMetrics: $("appsecMetrics"),
      phasePanelTitle: $("phasePanelTitle"),
      appsecHandoff: $("appsecHandoff"),
      appsecRepro: $("appsecRepro"),
      appsecWarRoomSummary: $("appsecWarRoomSummary"),
      runBaselineBtn: $("runBaselineBtn"),
      runExploitBtn: $("runExploitBtn"),
      confirmRootCauseBtn: $("confirmRootCauseBtn"),
      patchBuilder: $("patchBuilder"),
      applyPatchBtn: $("applyPatchBtn"),
      deploymentPackage: $("deploymentPackage"),
      inspectCodeBtn: $("inspectCodeBtn"),
      testPatchBtn: $("testPatchBtn"),
      deployPatchBtn: $("deployPatchBtn"),
      regClock: $("regClock"),
      legalFacts: $("legalFacts"),
      legalDecision: $("legalDecision"),
      complianceMetrics: $("complianceMetrics"),
      legalHandoff: $("legalHandoff"),
      acceptLegalHandoffBtn: $("acceptLegalHandoffBtn"),
      dataClassificationGrid: $("dataClassificationGrid"),
      exposureAssessment: $("exposureAssessment"),
      saveExposureBtn: $("saveExposureBtn"),
      notificationDecision: $("notificationDecision"),
      legalRationale: $("legalRationale"),
      recordLegalDecisionBtn: $("recordLegalDecisionBtn"),
      notificationCenter: $("notificationCenter"),
      approvalQueue: $("approvalQueue"),
      requestIsolationBtn: $("requestIsolationBtn"),
      requestLegalBtn: $("requestLegalBtn"),
      eventDrawer: $("eventDrawer"),
      contextMenu: $("contextMenu"),
      recentActions: $("recentActions"),
      pauseSimulationBtn: $("pauseSimulationBtn"),
      demoSpeedSelect: $("demoSpeedSelect"),
      toolChain: $("toolChain"),
      viewButtons: $("viewButtons"),
      nodeInspector: $("nodeInspector"),
      killchainDetail: $("killchainDetail")
      ,
      commanderCommandBar: $("commanderCommandBar"),
      commanderSituation: $("commanderSituation"),
      commanderDecisionActions: $("commanderDecisionActions"),
      stakeholderStatus: $("stakeholderStatus"),
      decisionTradeoffs: $("decisionTradeoffs"),
      commanderTimeline: $("commanderTimeline"),
      commanderDecisionLog: $("commanderDecisionLog")
      ,
      commanderAttackSummary: $("commanderAttackSummary"),
      commanderBriefings: $("commanderBriefings"),
      commanderBusinessImpact: $("commanderBusinessImpact")
    };

    const nodeInfo = {
      attacker: ["Attacker", "External source sending SQLi payloads and probing export paths."],
      waf: ["WAF", "Can detect, block, or rate-limit exploit patterns before they hit the app."],
      app: ["Web App", "The vulnerable customer endpoint that turns user input into SQL."],
      db: ["Database", "Contains customer data and audit logs needed for scope analysis."],
      soc: ["SOC", "Coordinates triage, evidence, containment, and monitoring."],
      legal: ["Legal", "Determines notification obligations from confirmed incident facts."]
    };

    const investigations = [
      { id: "ioc", label: "Hunt IoCs", desc: "Search IP, payload, user-agent, and session IDs.", score: 4, risk: -3, evidence: 7, note: "IoC hunt completed. Evidence quality improved and uncertainty dropped." },
      { id: "snapshot", label: "Snapshot logs", desc: "Preserve WAF, HTTP, DB, and IAM records.", score: 5, risk: -1, evidence: 9, note: "Logs preserved. Chain of custody is stronger." },
      { id: "owner", label: "Assign owners", desc: "SOC, engineering, legal, and business owner aligned.", score: 4, risk: -4, evidence: 3, note: "Owners assigned. Response speed and coordination improved." }
    ];

    const flowNames = ["Detect", "Scope", "Contain", "Recover", "Report"];
    const attackerStages = ["RECON", "INITIAL ACCESS", "EXPLOITATION", "DATA ACCESS", "CONTAINMENT", "REMEDIATION", "RECOVERY", "CLOSED"];

    const evidenceGameRows = [
      { id: "E-001", source: "HTTP", suspicious: false, confidence: "Low", ip: "198.51.100.24", time: "09:10:21", sourceHost: "web-prod-01", text: "09:10:21 GET /customers?id=12 200", details: "Normal customer lookup. Useful as baseline but not proof of exploitation." },
      { id: "E-002", source: "HTTP", suspicious: false, confidence: "Low", ip: "203.0.113.8", time: "09:10:25", sourceHost: "web-prod-01", text: "09:10:25 GET /customers?id=13 200", details: "Normal response from a different address. Helps compare response size." },
      { id: "E-003", source: "HTTP", suspicious: true, confidence: "High", ip: "198.51.100.24", time: "09:10:28", sourceHost: "web-prod-01", text: "09:10:28 GET /customers?id=12 UNION SELECT email,password_hash FROM users--", details: "Exploit payload returned HTTP 200 with response bytes 48,212, far above baseline." },
      { id: "E-004", source: "WAF", suspicious: true, confidence: "Medium", ip: "198.51.100.24", time: "09:12:07", sourceHost: "edge-waf-02", text: "09:12:07 SQLI_GENERIC_17 source=198.51.100.24 confidence=63%", details: "Signature matched UNION SELECT, comment marker, and customer endpoint path." },
      { id: "E-005", source: "DB", suspicious: true, confidence: "High", ip: "198.51.100.24", time: "09:13:44", sourceHost: "db-prod-01", text: "09:13:44 web_portal_ro accessed users records=247", details: "DB audit confirms unauthorized access to 247 customer records through the web role. External exfiltration is not established." },
      { id: "E-006", source: "IAM", suspicious: true, confidence: "Medium", ip: "198.51.100.24", time: "09:27:10", sourceHost: "iam-audit", text: "09:27:10 admin login from new ASN after hash access", details: "Potential credential follow-on activity. Needs correlation before declaring account compromise." },
      { id: "E-007", source: "Support", suspicious: true, confidence: "Medium", ip: "n/a", time: "09:19:33", sourceHost: "support-desk", text: "09:19:33 customer reports seeing another customer's profile data", details: "Customer report creates business impact, but technical correlation is still required." },
      { id: "E-008", source: "Support", suspicious: true, confidence: "Medium", ip: "n/a", time: "09:19:22", sourceHost: "support-queue", text: "09:19:22 customers report seeing another customer's profile data", details: "Customer-impact signal. Confirms unauthorized access risk, but does not establish external exfiltration." }
    ];

    const inboxAlerts = [
      { id: "waf", sev: "HIGH", title: "Possible SQL Injection", asset: "customer-portal-prod", real: true, sourceIp: "198.51.100.24", destination: "web-prod-01 / /customers", rule: "WAF SQLI_GENERIC_17", timestamp: "09:12:07", request: "GET /customers?id=12 UNION SELECT email,password_hash FROM users--", related: ["17 HTTP requests", "247 customer records accessed", "DB-8841 rows=247", "response bytes +420%"], detail: "Response size +420%. DB read anomaly within 8 sec. Source 198.51.100.24. External exfiltration is not established." },
      { id: "travel", sev: "MEDIUM", title: "Impossible travel", asset: "finance-admin", real: false, sourceIp: "203.0.113.44", destination: "idp-prod / finance-admin", rule: "IAM_TRAVEL_04", timestamp: "09:11:31", request: "SAML login from new VPN egress", related: ["Tirana to Frankfurt", "11 minutes", "no customer portal session", "no DB anomaly"], detail: "Tirana to Frankfurt in 11 minutes. Known corporate VPN: unknown. No DB anomaly linked." },
      { id: "powershell", sev: "LOW", title: "PowerShell execution", asset: "workstation-23", real: false, sourceIp: "10.18.42.23", destination: "workstation-23", rule: "EDR_SCRIPT_12", timestamp: "09:09:48", request: "powershell.exe -File inventory.ps1", related: ["signed script", "IT change window", "software-deploy.exe parent", "no lateral movement"], detail: "Signed inventory script, IT change window active, parent process software-deploy.exe." },
      { id: "dns", sev: "MEDIUM", title: "Suspicious DNS", asset: "marketing-laptop", real: false, sourceIp: "10.44.8.91", destination: "tracking-cdn.example", rule: "DNS_VOLUME_09", timestamp: "09:15:12", request: "high-volume DNS to tracking CDN", related: ["browser process", "ad campaign active", "no privileged access", "not linked to portal"], detail: "High DNS volume to tracking CDN. Asset has no customer portal session or privileged access." }
    ];

    const killGameItems = [
      { id: "kg1", text: "GET /admin/export", phase: "Recon" },
      { id: "kg2", text: "UNION SELECT users", phase: "Exploit" },
      { id: "kg3", text: "users table queried", phase: "Enumerate" },
      { id: "kg4", text: "WAF rule set to block", phase: "Contain" },
      { id: "kg5", text: "scope report generated", phase: "Recover" }
    ];

    const killChainDetails = [
      ["Recon", "The attacker probes routes, parameters, and export paths to discover where input reaches SQL."],
      ["Exploit", "The attacker confirms SQL Injection with UNION SELECT and begins extracting fields."],
      ["Enumerate", "The attacker scans table names, row counts, and sensitive columns to increase impact."],
      ["Contain", "Defenders block payloads, rotate credentials, preserve evidence, and deploy a tested patch."],
      ["Recover", "Teams validate clean state, report scope, notify stakeholders, and add durable controls."]
    ];

    const killChainSims = [
      {
        text: "Recon is the quiet first stage. The attacker is not stealing data yet; they are learning routes, parameters, response shapes, and hidden export functions.",
        tools: [
          ["Proxy", "Capture /customers?id=12 and compare normal vs unusual responses."],
          ["Access logs", "Look for repeated parameter changes, 404 discovery, and admin path probing."],
          ["SIEM", "Correlate source IP, user-agent, and frequency before exploitation starts."]
        ]
      },
      {
        text: "Exploit is where the CTF flag becomes a real incident. The payload proves that user input can change the SQL query and expose data.",
        tools: [
          ["WAF", "Detect UNION SELECT, information_schema, comment markers, and stacked-query attempts."],
          ["DB audit", "Confirm table scans and unusual row counts from the web application role."],
          ["SOC ticket", "Open severity-high incident and preserve the first exploit timestamps."]
        ]
      },
      {
        text: "Enumeration expands impact. The attacker tries to discover table names, sensitive columns, row counts, and useful credentials.",
        tools: [
          ["Query logs", "Identify which tables and columns were accessed."],
          ["IAM", "Check whether service credentials were reused or rotated too slowly."],
          ["Data map", "Classify affected records: email, phone, password hashes, payment references."]
        ]
      },
      {
        text: "Containment must stop active exploitation without destroying evidence or causing unnecessary downtime.",
        tools: [
          ["WAF block", "Move verified SQLi rule from monitor to block mode."],
          ["Patch pipeline", "Deploy parameterized query fix with health monitoring."],
          ["Credential rotation", "Rotate web_portal_ro and reduce database permissions."]
        ]
      },
      {
        text: "Recovery proves that the system is clean and the organization learned. This is where the incident becomes a permanent security improvement.",
        tools: [
          ["Validation", "Confirm no payloads pass and no suspicious DB reads continue."],
          ["Report", "Document timeline, scope, impact, decisions, and unknowns."],
          ["Runbook", "Create response playbook, SAST rule, and future tabletop exercise."]
        ]
      }
    ];

    const promptLabels = {
      next: "What should we do next?",
      exec: "Explain this to executives",
      legal: "What does legal need?"
    };

    const roles = [
      ["SOC Analyst", "Prioritize alerts, preserve evidence, and build a timeline from signals."],
      ["Incident Commander", "Coordinate owners, decisions, business impact, and response tempo."],
      ["AppSec Engineer", "Validate root cause, patch safely, and prevent the vulnerability from returning."],
      ["Legal/Compliance", "Separate confirmed facts from assumptions and manage notification obligations."]
    ];

    const demoAccounts = {
      "maya.chen": {
        name: "Maya Chen",
        username: "maya.chen",
        role: "SOC Analyst",
        shift: "Morning",
        clearance: "IR-L2",
        accessLevel: "L2 Incident Response"
      },
      "commander": {
        name: "Arben K.",
        username: "commander",
        role: "Incident Commander",
        shift: "On-call",
        clearance: "IR-CMD",
        accessLevel: "Incident Command"
      },
      "appsec": {
        name: "Nora Patel",
        username: "appsec",
        role: "AppSec Engineer",
        shift: "Product Security",
        clearance: "APPSEC-L3",
        accessLevel: "Application Security"
      },
      "legal": {
        name: "Elira Hoxha",
        username: "legal",
        role: "Legal/Compliance",
        shift: "Compliance Desk",
        clearance: "GRC-L2",
        accessLevel: "Legal Review"
      }
    };

    const SESSION_KEY = "incident-response-simulator-session";

    const roleAccess = {
      "SOC Analyst": {
        home: "warroom",
        pages: ["warroom", "wafalert", "inbox", "evidence", "ai", "approvals", "reportbuilder"],
        modules: ["Dashboard", "WAF Alert", "SOC Inbox", "Evidence Center", "AI Copilot", "Approvals", "Report Builder"],
        console: ["access granted: SIEM, WAF, HTTP logs", "primary mission: validate alert and preserve evidence", "restricted: legal notification authority"]
      },
      "Incident Commander": {
        home: "warroom",
        pages: ["warroom", "inbox", "comms", "approvals", "ai", "reportbuilder"],
        modules: ["Dashboard", "Incident Updates", "Crisis Comms", "Approvals", "AI Command Advisor", "Executive Report"],
        console: ["access granted: status board, comms, business impact", "primary mission: coordinate owners and decisions", "restricted: raw credential material"]
      },
      "AppSec Engineer": {
        home: "warroom",
        pages: ["warroom", "appsec", "evidence", "ai", "reportbuilder"],
        modules: ["Dashboard", "AppSec Workspace", "AppSec Evidence", "AI AppSec Assistant", "Remediation Report"],
        console: ["access granted: code trace, reproduction lab, patch pipeline, regression tests", "primary mission: reproduce, confirm root cause, remediate, and request deployment", "restricted: incident declaration, legal notification, executive containment authority"]
      },
      "Legal/Compliance": {
        home: "warroom",
        pages: ["warroom", "legal", "comms", "evidence", "ai", "reportbuilder"],
        modules: ["Dashboard", "Legal Assessment", "Communications Approval", "Compliance Evidence", "AI Legal Assistant", "Compliance Report"],
        console: ["access granted: incident facts, data categories, communication drafts", "primary mission: assess notification duties and document legal decision", "restricted: raw exploit tooling and production remediation"]
      }
    };

    function saveSession(account) {
      try {
        window.localStorage.setItem(SESSION_KEY, JSON.stringify({ username: account.username }));
      } catch (error) {
        // Training still works if storage is unavailable.
      }
    }

    function clearSavedSession() {
      try {
        window.localStorage.removeItem(SESSION_KEY);
      } catch (error) {
        // Nothing to clear when storage is unavailable.
      }
    }

    function restoreSavedSession() {
      try {
        const saved = JSON.parse(window.localStorage.getItem(SESSION_KEY) || "null");
        const account = saved?.username ? demoAccounts[saved.username] : null;
        if (!account) return;
        state.user = account;
        state.role = account.role;
        state.loggedIn = true;
        state.selectedLoginRole = null;
      } catch (error) {
        clearSavedSession();
      }
    }

    const comms = [
      ["cto", "urgent", "CTO", "Are customers exposed right now?", "Reply with current risk, confirmed facts, and next update time."],
      ["legal", "urgent", "Legal", "Do we have a reportable breach?", "Answer with data classes, confidence level, and unknowns."],
      ["support", "", "Support", "Customers are asking why profiles look wrong.", "Provide safe customer-facing wording and escalation path."],
      ["dev", "", "Engineering", "Patch is ready. Can we deploy?", "Approve only with evidence preserved, WAF plan, and health monitoring."]
    ];

    const reportEvidence = [
      ["http", "HTTP logs", "Shows exploit payload, source IP, route, and timestamps."],
      ["db", "DB audit", "Proves table scans and affected data classes."],
      ["waf", "WAF alert", "Confirms SQLi signatures and containment blocking."],
      ["iam", "IAM logs", "Shows service account use and credential rotation."],
      ["support", "Customer ticket", "Connects technical incident to real customer impact."],
      ["patch", "Patch diff", "Documents root-cause remediation with parameterized query."]
    ];

    const phaseBriefings = [
      {
        attacker: "Testing SQLi payloads, enumerating tables, and learning which fields can be extracted.",
        defender: "Decide whether this is active exploitation, preserve first evidence, and assign an incident owner.",
        business: "Customer data may be involved, but the facts are still incomplete.",
        success: "Incident opened, evidence preserved, and no destructive changes made before triage."
      },
      {
        attacker: "Moving from proof-of-exploit to larger table scans and possible credential discovery.",
        defender: "Build a defensible scope from SIEM, DB audit, IAM, WAF, and customer reports.",
        business: "Legal and leadership need confidence: confirmed, likely, and unknown exposure.",
        success: "Clear timeline, affected data classes, related accounts, and confidence level."
      },
      {
        attacker: "Repeating payloads while the endpoint is still reachable and the WAF is not fully blocking.",
        defender: "Reduce active risk with WAF controls, credential rotation, and a tested application patch.",
        business: "The portal has active users, so containment must avoid unnecessary downtime.",
        success: "Exploit path blocked, patch deployed, service monitored, and evidence retained."
      },
      {
        attacker: "No longer passing SQLi payloads, but the organization still needs to close gaps.",
        defender: "Finalize timeline, scope, actions, and long-term controls.",
        business: "Executives need impact, obligations, recovery status, and prevention plan.",
        success: "Evidence-backed report, runbook, owners, and engineering security improvements."
      }
    ];

    function money(value) {
      if (value >= 1000000) return `€${(value / 1000000).toFixed(1)}M`;
      if (value >= 1000) return `€${Math.round(value / 1000)}k`;
      return `€${value}`;
    }

    function duration(value) {
      if (value === null || value === undefined) return "--";
      const minutes = Math.floor(value / 60).toString().padStart(2, "0");
      const seconds = Math.floor(value % 60).toString().padStart(2, "0");
      return `${minutes}:${seconds}`;
    }

    function durationBetween(start, end) {
      if (start === null || start === undefined || end === null || end === undefined) return "--";
      return duration(Math.max(0, end - start));
    }

    function clamp(value, min, max) {
      return Math.max(min, Math.min(max, value));
    }

    function current() {
      return phases[state.phase];
    }

    function typeText(element, text) {
      element.textContent = "";
      let i = 0;
      const step = () => {
        element.textContent = text.slice(0, i);
        i += 1;
        if (i <= text.length) window.setTimeout(step, 11);
      };
      step();
    }

    function incidentTime(offsetSeconds = state.elapsedSeconds) {
      const baseMinutes = 12 + Math.floor(offsetSeconds / 60);
      const hours = 9 + Math.floor(baseMinutes / 60);
      const minutes = baseMinutes % 60;
      return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
    }

    function logAction(action, actor = state.user ? state.user.name : state.role) {
      state.actionTimeline.push({ time: incidentTime(), actor, action });
      if (state.actionTimeline.length > 24) state.actionTimeline.shift();
      renderRecentActions();
    }

    function socValidated() {
      return state.inboxStatuses.waf === "INVESTIGATING" || state.inboxStatuses.waf === "ESCALATED" || Boolean(state.collectedEvidence["E-003"] || state.collectedEvidence["E-004"]);
    }

    function socScoped() {
      return Boolean(state.collectedEvidence["E-003"] && state.collectedEvidence["E-004"] && state.collectedEvidence["E-005"]);
    }

    function commandReady() {
      return socScoped() && state.inboxStatuses.waf === "ESCALATED" && state.approvals.some(item => item.owner === "Incident Commander" || item.type.includes("Portal") || item.type.includes("SQL"));
    }

    function appsecReady() {
      return Boolean(state.commandDecision && state.commandDecision !== "continue monitoring" && state.commandDecision !== "block source IP only");
    }

    function legalReady() {
      return socScoped() && (Boolean(state.commandDecision) || state.commandComms.legal || state.recordsExposed !== null);
    }

    function roleEngagementStatus(role) {
      if (role === "SOC Analyst") return "Active triage owner";
      if (role === "Incident Commander") return commandReady() ? "Command action required" : "Monitoring incident";
      if (role === "AppSec Engineer") return appsecReady() ? "Remediation handoff available" : "Standby - no active remediation assignment";
      if (role === "Legal/Compliance") return legalReady() ? "Legal handoff available" : "Monitoring - insufficient confirmed facts";
      return "Available";
    }

    function roleLandingDetails(role) {
      const map = {
        "SOC Analyst": {
          icon: "◉",
          title: "SOC Analyst",
          focus: "Investigation & Triage",
          summary: "Investigate alerts and build evidence.",
          status: "ACTIVE",
          statusClass: "active",
          briefing: "A HIGH-severity alert has been generated against the production customer portal. Determine whether the activity represents a real incident. Collect evidence before escalating.",
          objective: "Validate the suspicious WAF alert."
        },
        "Incident Commander": {
          icon: "◆",
          title: "Incident Commander",
          focus: "Command & Coordination",
          summary: "Coordinate response and make decisions.",
          status: commandReady() ? "ACTION REQUIRED" : "MONITORING",
          statusClass: commandReady() ? "active" : "monitoring",
          briefing: commandReady() ? "SOC has escalated an evidence-backed incident. Review confidence, business impact, containment choices, and stakeholder needs before authorizing action." : "You can monitor business health and request status updates. No command decision is required until SOC escalates confirmed evidence.",
          objective: commandReady() ? "Accept command and choose a containment path." : "Monitor the incident and keep decision context current."
        },
        "AppSec Engineer": {
          icon: "&lt;/&gt;",
          title: "AppSec Engineer",
          focus: "Application Security",
          summary: "Investigate and remediate the app.",
          status: appsecReady() ? "HANDOFF AVAILABLE" : "STANDBY",
          statusClass: appsecReady() ? "active" : "standby",
          briefing: appsecReady() ? "Commander has assigned AppSec to validate the vulnerable endpoint. Reproduce the exploit safely, confirm root cause, apply the parameterized-query fix, and request deployment approval." : "You can review application ownership and public incident context. Remediation actions remain gated until Commander assigns AppSec.",
          objective: appsecReady() ? "Accept the remediation handoff." : "Review context without starting remediation prematurely."
        },
        "Legal/Compliance": {
          icon: "§",
          title: "Legal / Compliance",
          focus: "Legal & Regulatory Response",
          summary: "Assess data exposure and obligations.",
          status: legalReady() ? "HANDOFF AVAILABLE" : "MONITORING",
          statusClass: legalReady() ? "active" : "monitoring",
          briefing: legalReady() ? "Confirmed facts indicate possible personal-data involvement. Classify data, assess exposure, record rationale, and approve evidence-backed communications." : "You can monitor personal-data indicators and request confirmed facts. Breach conclusions remain gated until evidence supports them.",
          objective: legalReady() ? "Accept legal handoff and assess exposure." : "Monitor facts and avoid premature legal conclusions."
        }
      };
      return map[role] || map["SOC Analyst"];
    }

    function openRoleBriefing(account) {
      const details = roleLandingDetails(account.role);
      openDrawer(`Welcome, ${details.title}`, `
        <div class="report-section"><strong>Workspace</strong><span>${details.focus}</span></div>
        <div class="report-section"><strong>Scenario</strong><span>INC-2026-0812 — Potential Web Exploitation against customer-portal-prod.</span></div>
        <div class="report-section"><strong>Briefing</strong><span>${details.briefing}</span></div>
        <div class="report-section"><strong>Your first objective</strong><span>${details.objective}</span></div>
        <div class="actions"><button class="btn primary" id="startRoleBriefingBtn" type="button">${account.role === "SOC Analyst" ? "Start investigation" : "Enter workspace"}</button></div>`);
      $("startRoleBriefingBtn")?.addEventListener("click", () => els.eventDrawer.classList.remove("open"));
    }

    function dataAccessStatus() {
      if (state.recordsExposed !== null || state.legalExposureSaved || state.legalDecisionRecorded) return "Confirmed records accessed: 247";
      if (state.collectedEvidence["E-005"]) return "Potentially affected: 247";
      return "Unknown";
    }

    function workflowAttackStage() {
      if (state.reportReadiness >= 85 && state.patchDeployed && state.legalDecisionRecorded) return "CLOSED";
      if (state.patchDeployed) return "RECOVERY";
      if (state.appsecDeploymentRequested || state.patchTested) return "REMEDIATION";
      if (state.commandDecision || state.appliedRecs.contain || state.containmentTime !== null) return "CONTAINMENT";
      if (state.collectedEvidence["E-005"] || state.recordsExposed !== null) return "DATA ACCESS";
      if (state.collectedEvidence["E-003"] || state.collectedEvidence["E-004"] || state.inboxStatuses.waf === "INVESTIGATING") return "EXPLOITATION";
      if (state.inboxStatuses.waf === "ASSIGNED") return "INITIAL ACCESS";
      return "RECON";
    }

    function updateHandoff(target, summary) {
      const handoff = state.handoffs[target];
      if (!handoff) return;
      handoff.version += 1;
      handoff.updatedAt = state.elapsedSeconds;
      handoff.summary = summary;
    }

    function handoffLine(target) {
      const handoff = state.handoffs[target];
      if (!handoff || !handoff.version) return "No active handoff";
      const stale = state.handoffViews[target] < handoff.version;
      return `Handoff v${handoff.version} — ${handoff.summary}${stale ? " | Update available" : ""}`;
    }

    function markHandoffViewed(target) {
      if (state.handoffs[target]) state.handoffViews[target] = state.handoffs[target].version;
    }

    function closureBlockers() {
      const blockers = [];
      if (!socScoped()) blockers.push("SOC scope not complete");
      if (!state.commanderAccepted || !state.commandDecision) blockers.push("Commander decision missing");
      if (!state.patchTested || !state.patchDeployed) blockers.push("Exploit remediation not deployed");
      if (state.monitoringStableSince === null) blockers.push("Production monitoring window not stable");
      if (!state.recoveryAuthorized) blockers.push("Commander recovery authorization missing");
      if (!state.legalDecisionRecorded) blockers.push("Legal disposition not recorded");
      if (Object.keys(state.legalComms).length < 2) blockers.push("Legal communications review incomplete");
      return blockers;
    }

    function maybeIncidentInjects() {
      const inject = (id, atSeconds, fn) => {
        if (state.injectsSeen[id] || state.elapsedSeconds < atSeconds) return;
        state.injectsSeen[id] = true;
        fn();
      };
      inject("support-complaints", 75, () => {
        state.supportComplaints += 7;
        state.risk = clamp(state.risk + 2, 0, 100);
        updateHandoff("commander", "Customer Support reports +7 profile-data complaints; business impact needs review.");
        updateHandoff("legal", "Customer complaints indicate possible personal-data access; facts remain incomplete.");
        logAction("Inject: Customer Support reports +7 profile-data complaints", "Customer Support");
        toast("Incident inject", "Customer Support: +7 profile-data complaints.", "bad");
      });
      inject("new-source-ip", 135, () => {
        if (state.commandDecision === "block source IP only") state.risk = clamp(state.risk + 9, 0, 100);
        updateHandoff("commander", "WAF detected a second source IP; source-only blocking may be insufficient.");
        logAction("Inject: WAF detected a second source IP using similar SQLi payload", "WAF");
        toast("Incident inject", "WAF: new source IP detected.", "bad");
      });
      inject("cto-status", 180, () => {
        logAction("Inject: CTO requested an executive status update", "CTO");
        if (!state.commandComms.cto) state.loss += 7000;
        toast("Incident inject", "CTO requests a status update.");
      });
      inject("patch-eta-slip", 260, () => {
        if (state.appsecHandoffAccepted && !state.patchTested) {
          state.risk = clamp(state.risk + 4, 0, 100);
          updateHandoff("commander", "Engineering reports PATCH-204 ETA slipped by 10 minutes.");
          logAction("Inject: PATCH-204 ETA slipped by 10 minutes", "Engineering");
          toast("Incident inject", "Engineering: patch ETA slipped by 10 minutes.", "bad");
        }
      });
      if (state.patchDeployed && state.monitoringStableSince === null && state.incidentClock.recoveredAt !== null && state.elapsedSeconds - state.incidentClock.recoveredAt >= 35) {
        state.monitoringStableSince = state.elapsedSeconds;
        updateHandoff("commander", "Post-deployment monitoring stable: SQLi attempts blocked, DB anomalies 0, service health normal.");
        logAction("Monitoring window stable: SQLi attempts 14, successful exploitation 0, DB anomalies 0", "Telemetry");
        toast("Recovery validation", "Production monitoring window is stable.");
      }
    }

    function renderRecentActions() {
      if (!els.recentActions) return;
      els.recentActions.innerHTML = state.actionTimeline.slice(-7).reverse().map(item => `<div class="timeline-row">
        <b>${item.time}</b>
        <span>${item.actor}: ${item.action}</span>
      </div>`).join("");
    }

    function objectiveItems() {
      if (state.role === "AppSec Engineer") {
        return [
          [
            "Reproduce and remediate suspected SQL injection",
            [
              ["Review SOC handoff", state.appsecHandoffAccepted],
              ["Reproduce exploit safely", state.appsecExploitReproduced],
              ["Inspect vulnerable endpoint", state.appsecTraceInspected]
            ]
          ],
          [
            "Confirm root cause and build fix",
            [
              ["Confirm dynamic SQL root cause", state.appsecRootCauseConfirmed],
              ["Select parameterized query remediation", state.appsecSelectedPatch === "parameterized"],
              ["Apply PATCH-204", state.appsecPatchApplied]
            ]
          ],
          [
            "Validate remediation",
            [
              ["Run security regression suite", state.patchTested],
              ["Review code diff", state.appsecPatchApplied],
              ["Residual risk low", state.patchTested && state.appsecPatchApplied]
            ]
          ],
          [
            "Request production deployment",
            [
              ["Deployment package prepared", state.patchTested],
              ["Sent to Incident Commander", state.appsecDeploymentRequested || state.patchDeployed],
              ["Deployment approved", state.patchDeployed]
            ]
          ]
        ];
      }
      return [
        [
          "Validate the WAF alert",
          [
            ["Open WAF alert", state.wafAlertOpened || state.inboxStatuses.waf === "INVESTIGATING" || state.inboxStatuses.waf === "ESCALATED"],
            ["Correlate related HTTP traffic", state.terminalLines.some(line => line.includes("12 events found")) || state.collectedEvidence["E-003"]],
            ["Collect one supporting artifact", Object.keys(state.collectedEvidence).length > 0]
          ]
        ],
        [
          "Determine scope of compromise",
          [
            ["Preserve HTTP/WAF/DB evidence", ["E-003", "E-004", "E-005"].filter(id => state.collectedEvidence[id]).length >= 2],
            ["Confirm affected data classes", state.recordsExposed !== null || state.collectedEvidence["E-005"]],
            ["Brief legal or commander", state.approvals.length > 0 || Object.keys(state.answeredMessages).length > 0]
          ]
        ],
        [
          "Contain active exploitation",
          [
            ["Preserve snapshot", state.terminalLines.some(line => line.includes("snapshot acquired"))],
            ["Block active SQLi payload", state.appliedRecs.contain || state.terminalLines.some(line => line.includes("promoted to BLOCK"))],
            ["Request/receive approval", state.approvals.some(item => item.status === "approved")]
          ]
        ],
        [
          "Recover and report",
          [
            ["Patch tested", state.patchTested],
            ["Production deploy requested", state.patchDeployed],
            ["Report readiness >= 80%", state.reportReadiness >= 80]
          ]
        ]
      ];
    }

    function renderMetrics() {
      if (els.score) els.score.textContent = state.score;
      els.attackerProgressMetric.textContent = `${state.attackerProgress}%`;
      els.risk.textContent = `${state.risk}%`;
      els.evidence.textContent = `${state.evidence}%`;
      els.loss.textContent = state.loss > 250000 ? "HIGH" : state.loss > 50000 ? "MEDIUM" : "LOW";
      els.assetsAffected.textContent = String(1 + Math.floor(state.attackerProgress / 34));
      els.recordsExposed.textContent = dataAccessStatus();
      els.scoreBar.style.width = `${state.attackerProgress}%`;
      els.riskBar.style.width = `${state.risk}%`;
      els.evidenceBar.style.width = `${state.evidence}%`;
      els.lossBar.style.width = `${clamp(state.loss, 0, 1000000) / 1000000 * 100}%`;
      els.assetsBar.style.width = `${clamp((1 + Math.floor(state.attackerProgress / 34)) * 25, 0, 100)}%`;
      els.recordsBar.style.width = `${state.recordsExposed === null ? state.collectedEvidence["E-005"] ? 48 : 12 : clamp(state.recordsExposed / 200, 0, 100)}%`;
      const workflowStage = workflowAttackStage();
      const stageIndex = attackerStages.indexOf(workflowStage);
      if (stageIndex > state.stageIndex) {
        state.stageIndex = stageIndex;
        toast("INCIDENT ESCALATION", `Incident stage changed to ${workflowStage}.`, workflowStage === "DATA ACCESS" ? "bad" : "good");
      }
      els.attackerStage.textContent = workflowStage;
      const detected = state.detectedTime !== null;
      const contained = state.risk < 35 || state.appliedRecs.contain || state.containmentTime !== null;
      if (contained && state.containmentTime === null) state.containmentTime = state.elapsedSeconds;
      if (els.mttdMetric) els.mttdMetric.textContent = detected ? `${Math.max(1, Math.floor(state.detectedTime / 60))}m` : "--";
      if (els.mttcMetric) els.mttcMetric.textContent = contained ? `${Math.max(2, Math.floor((state.containmentTime || state.elapsedSeconds) / 60))}m` : "--";
      if (els.serviceHealthMetric) els.serviceHealthMetric.textContent = `${state.serviceHealth}%`;
      if (els.mttdBar) els.mttdBar.style.width = `${detected ? clamp(100 - state.detectedTime / 6, 18, 100) : 4}%`;
      if (els.mttcBar) els.mttcBar.style.width = `${contained ? 100 : clamp(state.risk, 8, 92)}%`;
      if (els.serviceHealthBar) els.serviceHealthBar.style.width = `${state.serviceHealth}%`;
      const minutes = Math.floor(state.elapsedSeconds / 60).toString().padStart(2, "0");
      const seconds = (state.elapsedSeconds % 60).toString().padStart(2, "0");
      els.incidentTimer.textContent = `${minutes}:${seconds}`;
      if (state.role === "Incident Commander") renderCommanderWarRoom();
      if (state.role === "AppSec Engineer") renderAppSec();
      if (state.role === "Legal/Compliance") renderLegal();
    }

    function toast(title, message, type = "good") {
      if (!els.toastStack) return;
      const node = document.createElement("div");
      node.className = "toast";
      node.innerHTML = `<b>${title}</b><span class="small">${message}</span>`;
      els.toastStack.appendChild(node);
      window.setTimeout(() => node.remove(), 2600);
    }

    function adjustMetric(key, amount, reason) {
      if (key === "risk") state.risk = clamp(state.risk + amount, 0, 100);
      if (key === "evidence") state.evidence = clamp(state.evidence + amount, 0, 100);
      if (key === "attacker") state.attackerProgress = clamp(state.attackerProgress + amount, 0, 100);
      toast(amount >= 0 && key !== "risk" ? `${reason} +${Math.abs(amount)}%` : `${reason} ${amount > 0 ? "+" : ""}${amount}%`, `${key} updated`, amount > 0 ? "good" : "bad");
      renderMetrics();
    }

    function renderObjective() {
      if (!els.objectiveText) return;
      if (state.role === "Incident Commander") {
        renderCommanderWarRoom();
        return;
      }
      if (state.role === "AppSec Engineer") {
        const objectives = [
          {
            title: "Reproduce and remediate suspected SQL injection",
            text: "SOC handed off a suspected exploit. Prove exploitability in a safe lab and trace the endpoint to code.",
            actions: [["Open AppSec workspace", () => showPage("appsec")], ["Run safe reproduction", () => { showPage("appsec"); if (els.runExploitBtn) els.runExploitBtn.click(); }], ["Inspect endpoint", () => { showPage("appsec"); els.inspectCodeBtn.click(); }]]
          },
          {
            title: "Confirm root cause and build fix",
            text: "Confirm dynamic SQL construction, then apply a remediation that removes the root cause.",
            actions: [["Confirm root cause", () => { showPage("appsec"); if (els.confirmRootCauseBtn) els.confirmRootCauseBtn.click(); }], ["Open Patch Builder", () => showPage("appsec")], ["Ask AI to challenge patch", () => { showPage("ai"); renderAI("challenge"); }]]
          },
          {
            title: "Validate remediation",
            text: "Run security regression tests and prove the patch blocks SQLi without breaking normal behavior.",
            actions: [["Run test suite", () => { showPage("appsec"); els.testPatchBtn.click(); }], ["Review AI tests", () => { showPage("ai"); renderAI("tests"); }], ["Build report", () => showPage("reportbuilder")]]
          },
          {
            title: "Request production deployment",
            text: "Package PATCH-204 for Incident Commander approval and verify the remediation status.",
            actions: [["Request deployment", () => { showPage("appsec"); els.deployPatchBtn.click(); }], ["Open approvals", () => showPage("approvals")], ["Remediation report", () => showPage("reportbuilder")]]
          }
        ];
        const item = objectives[Math.min(state.objectiveStep, objectives.length - 1)];
        const progress = objectiveItems()[Math.min(state.objectiveStep, objectives.length - 1)][1];
        const doneCount = progress.filter(step => step[1]).length;
        const oldProgress = document.querySelector(".objective-progress");
        if (oldProgress) oldProgress.remove();
        els.objectiveTitle.textContent = `Current objective: ${item.title}`;
        els.objectiveText.innerHTML = `${item.text}<br><strong>Progress ${doneCount} / ${progress.length}</strong>`;
        els.objectiveActions.innerHTML = item.actions.map((action, index) => `<button class="btn ${index === 0 ? "primary" : ""}" type="button" data-objective-action="${index}">${action[0]}</button>`).join("");
        els.objectiveActions.insertAdjacentHTML("beforebegin", `<div class="objective-progress">${progress.map(step => `<div class="objective-step ${step[1] ? "done" : ""}"><span>${step[1] ? "✓" : "○"}</span><span>${step[0]}</span></div>`).join("")}</div>`);
        els.objectiveActions.querySelectorAll("button").forEach(button => button.addEventListener("click", () => item.actions[Number(button.dataset.objectiveAction)][1]()));
        if (doneCount === progress.length && state.objectiveStep < objectives.length - 1) {
          state.objectiveStep += 1;
          logAction(`AppSec objective complete: ${item.title}`);
          toast("OBJECTIVE COMPLETE", `New AppSec objective: ${objectives[state.objectiveStep].title}.`);
          renderObjective();
        }
        return;
      }
      if (state.role === "Legal/Compliance") {
        const objectives = [
          {
            title: "Accept legal handoff and assess exposure",
            text: "Review the incident facts, classify possible personal data, and avoid premature breach statements.",
            actions: [["Open Legal Assessment", () => showPage("legal")], ["Open Compliance Evidence", () => showPage("evidence")], ["Ask AI legal threshold", () => { showPage("ai"); renderAI("why"); }]]
          },
          {
            title: "Document notification decision",
            text: "Determine breach status, risk to individuals, authority notification, and data-subject communication posture.",
            actions: [["Save assessment", () => { showPage("legal"); if (els.saveExposureBtn) els.saveExposureBtn.click(); }], ["Record decision", () => { showPage("legal"); if (els.recordLegalDecisionBtn) els.recordLegalDecisionBtn.click(); }], ["Review comms", () => showPage("comms")]]
          },
          {
            title: "Approve communications and package record",
            text: "Approve only evidence-backed wording and preserve the rationale for audit/compliance review.",
            actions: [["Open Communications", () => showPage("comms")], ["Compliance report", () => showPage("reportbuilder")], ["AI challenge conclusion", () => { showPage("ai"); renderAI("challenge"); }]]
          }
        ];
        const item = objectives[Math.min(state.objectiveStep, objectives.length - 1)];
        const progressSets = [
          [["Legal handoff accepted", state.legalHandoffAccepted], ["Data classes selected", Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]).length >= 3], ["Exposure saved", state.legalExposureSaved]],
          [["Breach status decided", state.legalDecisionRecorded], ["Regulatory clock status known", state.legalClockStartedAt !== null || state.legalBreachStatus !== "CONFIRMED"], ["Rationale captured", Boolean(state.legalRationale)]],
          [["Communication reviewed", Object.keys(state.legalComms).length >= 2], ["Compliance report >= 85%", state.reportReadiness >= 85], ["Legal review complete", state.reportReadiness >= 85]]
        ];
        const progress = progressSets[Math.min(state.objectiveStep, progressSets.length - 1)];
        const doneCount = progress.filter(step => step[1]).length;
        const oldProgress = document.querySelector(".objective-progress");
        if (oldProgress) oldProgress.remove();
        els.objectiveTitle.textContent = `Current objective: ${item.title}`;
        els.objectiveText.innerHTML = `${item.text}<br><strong>Progress ${doneCount} / ${progress.length}</strong>`;
        els.objectiveActions.innerHTML = item.actions.map((action, index) => `<button class="btn ${index === 0 ? "primary" : ""}" type="button" data-objective-action="${index}">${action[0]}</button>`).join("");
        els.objectiveActions.insertAdjacentHTML("beforebegin", `<div class="objective-progress">${progress.map(step => `<div class="objective-step ${step[1] ? "done" : ""}"><span>${step[1] ? "✓" : "○"}</span><span>${step[0]}</span></div>`).join("")}</div>`);
        els.objectiveActions.querySelectorAll("button").forEach(button => button.addEventListener("click", () => item.actions[Number(button.dataset.objectiveAction)][1]()));
        if (doneCount === progress.length && state.objectiveStep < objectives.length - 1) {
          state.objectiveStep += 1;
          logAction(`Legal objective complete: ${item.title}`);
          toast("OBJECTIVE COMPLETE", `New Legal objective: ${objectives[state.objectiveStep].title}.`);
          renderObjective();
        }
        return;
      }
      const objectives = [
        {
          title: "Validate the WAF alert",
          text: "Determine whether the WAF alert represents real exploitation or a false positive.",
          actions: [["Open WAF alert", () => showPage("wafalert")], ["Search related traffic", () => runSocCommand("search ip 198.51.100.24")], ["Collect first evidence", () => showPage("evidence")]]
        },
        {
          title: "Determine scope of compromise",
          text: "Correlate HTTP, WAF, DB, and support evidence to understand affected data.",
          actions: [["Open Evidence Center", () => showPage("evidence")], ["Run timeline", () => runSocCommand("timeline")], ["Ask AI missing evidence", () => { showPage("ai"); renderAI("missing"); }]]
        },
        {
          title: "Contain active exploitation",
          text: "Preserve evidence, then block the active pattern or request commander approval for isolation.",
          actions: [["Snapshot DB", () => runSocCommand("snapshot db")], ["Review block action", () => reviewAction("block")], ["Request approval", () => showPage("approvals")]]
        },
        {
          title: "Recover and report",
          text: "Validate remediation, complete report readiness, and close with a defensible scorecard.",
          actions: [["Open AppSec", () => showPage("appsec")], ["Build report", () => showPage("reportbuilder")], ["Final scorecard", showReport]]
        }
      ];
      const item = objectives[Math.min(state.objectiveStep, objectives.length - 1)];
      const progress = objectiveItems()[Math.min(state.objectiveStep, objectives.length - 1)][1];
      const doneCount = progress.filter(step => step[1]).length;
      const oldProgress = document.querySelector(".objective-progress");
      if (oldProgress) oldProgress.remove();
      els.objectiveTitle.textContent = `Current objective: ${item.title}`;
      els.objectiveText.innerHTML = `${item.text}<br><strong>Progress ${doneCount} / ${progress.length}</strong>`;
      els.objectiveActions.innerHTML = item.actions.map((action, index) => `<button class="btn ${index === 0 ? "primary" : ""}" type="button" data-objective-action="${index}">${action[0]}</button>`).join("");
      els.objectiveActions.insertAdjacentHTML("beforebegin", `<div class="objective-progress">${progress.map(step => `<div class="objective-step ${step[1] ? "done" : ""}"><span>${step[1] ? "✓" : "○"}</span><span>${step[0]}</span></div>`).join("")}</div>`);
      els.objectiveActions.querySelectorAll("button").forEach(button => button.addEventListener("click", () => item.actions[Number(button.dataset.objectiveAction)][1]()));
      if (doneCount === progress.length && state.objectiveStep < objectives.length - 1) {
        state.objectiveStep += 1;
        logAction(`Objective complete: ${item.title}`);
        toast("OBJECTIVE COMPLETE", `Incident confidence increased. New objective: ${objectives[state.objectiveStep].title}.`);
        renderObjective();
      }
    }

    function commanderConfidence() {
      return clamp(52 + state.evidence * .35 + (state.inboxStatuses.waf === "INVESTIGATING" ? 10 : 0), 35, 88);
    }

    function renderCommanderWarRoom() {
      if (!els.commanderCommandBar) return;
      const confidence = Math.round(commanderConfidence());
      const decisionSla = duration(Math.max(0, 180 - state.elapsedSeconds));
      const decisionSlaLabel = state.commanderSlaBreached ? "SLA BREACHED" : decisionSla;
      const exposure = state.recordsExposed === null ? "SUSPECTED" : `${state.recordsExposed.toLocaleString()} records`;
      const containment = state.containmentTime !== null || state.appliedRecs.contain ? "IN PROGRESS" : "NOT STARTED";
      els.commanderCommandBar.innerHTML = [
        ["Incident severity", "HIGH"],
        ["Business impact", state.loss > 120000 ? "HIGH" : state.loss > 20000 ? "MEDIUM" : "LOW"],
        ["Decision SLA", decisionSlaLabel],
        ["Containment", containment]
      ].map(item => `<div class="command-kpi ${item[1] === "SLA BREACHED" ? "bad" : ""}"><span class="small">${item[0]}</span><strong>${item[1]}</strong></div>`).join("");
      if (els.commandMetrics) {
        els.commandMetrics.innerHTML = [
          ["Severity", "HIGH"],
          ["Business impact", state.loss > 120000 ? "HIGH" : state.loss > 20000 ? "MEDIUM" : "LOW"],
          ["Customer impact", state.recordsExposed === null ? "LOW" : "ELEVATED"],
          ["Containment", containment],
          ["Decision SLA", decisionSlaLabel],
          ["Availability", `${state.serviceHealth}%`],
          ["Data access", state.recordsExposed === null ? "SUSPECTED" : "CONFIRMED"],
          ["Comms", Object.keys(state.commandComms).length >= 2 ? "ACTIVE" : "PENDING"]
        ].map(item => `<div class="card metric ${item[1] === "SLA BREACHED" ? "bad" : ""}"><span class="small">${item[0]}</span><strong>${item[1]}</strong>${item[0] === "Customer impact" && state.recordsExposed === null ? `<span class="small">Current assessed impact: low; exposure still under review.</span>` : ""}</div>`).join("");
      }
      const commanderHandoff = handoffLine("commander");
      els.commanderSituation.innerHTML = commandReady()
        ? `⚠ COMMAND ACTION REQUIRED. ${commanderHandoff}. Confidence is ${confidence}%. Customer data access is ${exposure}; external exfiltration is not established. Service health is ${state.serviceHealth}%.`
        : `COMMAND STATUS: monitoring incident. SOC confidence is ${confidence}%. Business impact is unknown. Containment request: none. Decision required: no. ${commanderHandoff}.`;
      const commanderActions = !commandReady()
        ? [["status", "Request SOC status update"], ["business", "Ask business impact"], ["support-watch", "Monitor support queue"]]
        : state.patchDeployed && state.monitoringStableSince !== null && !state.recoveryAuthorized
          ? [["authorizeRecovery", "Authorize recovery"], ["status", "Request SOC status update"], ["business", "Ask business impact"]]
          : [
              ["accept", state.commanderAccepted ? "Command accepted ✓" : "Accept command"],
              ["more", "Request more evidence"],
              ["targeted", "Restrict vulnerable endpoint"],
              ["blockip", "Block source IP only"],
              ["wait", "Continue monitoring"],
              ["isolate", "Shut down portal"]
            ];
      els.commanderDecisionActions.innerHTML = commanderActions.map((item, index) => `<button class="btn ${index === 0 || item[0] === "targeted" ? "primary" : ""}" type="button" data-command-decision="${item[0]}" ${item[0] === "accept" && state.commanderAccepted ? "disabled" : ""}>${item[1]}</button>`).join("");
      els.commanderDecisionActions.querySelectorAll("[data-command-decision]").forEach(button => button.addEventListener("click", () => applyCommanderDecision(button.dataset.commandDecision)));
      els.decisionTradeoffs.innerHTML = [
        ["Targeted containment", "Security +35%", "Availability -10%", "Customer impact -5%"],
        ["Block source IP only", "Security +12%", "Availability 0%", "Bypass risk remains"],
        ["Continue monitoring", "Evidence +8%", "Security -18%", "Attacker momentum rises"],
        ["Full portal isolation", "Security +60%", "Availability -70%", "Customer impact -35%"],
        ["Wait for evidence", "Evidence +20%", "Security -15%", "Time +3 min"]
      ].map(item => `<div class="tradeoff-card"><b>${item[0]}</b><span class="small">${item[1]}</span><span class="small">${item[2]}</span><span class="small">${item[3]}</span></div>`).join("");
      if (els.commanderAttackSummary) {
        els.commanderAttackSummary.innerHTML = [
          ["Attack status", state.attackerProgress > 58 ? "Escalating toward data access" : "Active exploitation suspected"],
          ["Evidence posture", `${Math.round(commanderConfidence())}% command confidence`],
          ["Customer portal", state.serviceHealth > 85 ? "Healthy; targeted containment preferred" : "Degraded; customer impact rising"]
        ].map(item => `<div class="tradeoff-card"><b>${item[0]}</b><span class="small">${item[1]}</span></div>`).join("");
      }
      els.stakeholderStatus.innerHTML = [
        ["SOC", state.inboxStatuses.waf === "INVESTIGATING" ? "Investigating" : "Awaiting triage"],
        ["AppSec", state.patchTested ? "Patch validated" : "Patch prepared"],
        ["Engineering", state.containmentTime ? "Executing approved action" : "Awaiting approval"],
        ["Legal", state.commandComms.legal ? "Legal review requested" : state.recordsExposed === null ? "Assessing exposure" : "Reviewing notification"],
        ["Support", state.commandComms.support ? "Holding statement sent" : state.collectedEvidence["E-007"] ? "Customer reports active" : "Monitoring reports"],
        ["CTO", state.commandComms.cto ? "Briefed" : "Awaiting briefing"]
      ].map(item => `<div class="stakeholder-row"><b>${item[0]}</b><span>${item[1]}</span></div>`).join("");
      els.commanderTimeline.innerHTML = state.actionTimeline.slice(-6).reverse().map(item => `<div class="timeline-row"><b>${item.time}</b><span>${item.actor}: ${item.action}</span></div>`).join("");
      els.commanderDecisionLog.innerHTML = state.actionTimeline.filter(item => item.actor.includes("Commander") || item.action.includes("Command") || item.action.includes("containment") || item.action.includes("evidence")).slice(-6).reverse().map(item => `<div class="timeline-row"><b>${item.time}</b><span>${item.action}</span></div>`).join("") || `<div class="ready-row"><span>?</span><span>No commander decisions yet.</span></div>`;
      if (els.commanderBriefings) {
        els.commanderBriefings.innerHTML = [
          ["SOC", `Confidence ${confidence}%; awaiting containment direction.`],
          ["DB Team", state.collectedEvidence["E-005"] ? "Read anomaly confirmed." : "DB scope update pending."],
          ["AppSec", state.patchTested ? "Patch validated for deployment." : "Patch prepared; tests pending."],
          ["Support", state.collectedEvidence["E-007"] ? "Customer reports need holding statement." : "Monitoring support queue."]
        ].map(item => `<div class="timeline-row"><b>${item[0]}</b><span>${item[1]}</span></div>`).join("");
      }
      if (els.commanderBusinessImpact) {
        els.commanderBusinessImpact.innerHTML = [
          ["Portal", state.serviceHealth > 85 ? "Healthy" : "Degraded"],
          ["Customers", state.recordsExposed === null ? "At risk" : "Potential exposure"],
          ["Data", state.recordsExposed === null ? "Unknown" : "Confirmed scope"],
          ["Legal", state.commandComms.legal ? "Legal review requested" : "Waiting"]
        ].map(item => `<div class="status-light ${item[1].includes("Healthy") || item[1].includes("Briefed") || item[1].includes("requested") ? "good" : "warn"}"><span>${item[0]}</span><b>${item[1]}</b></div>`).join("");
      }
    }

    function applyCommanderDecision(action) {
      if (action === "status") {
        markHandoffViewed("commander");
        state.evidence = clamp(state.evidence + 3, 0, 100);
        logAction("Commander requested latest SOC status update", "Incident Commander");
        toast("Status requested", "Commander view refreshed against latest SOC handoff.");
        renderMetrics();
        renderCommanderWarRoom();
        renderReportBuilder();
        return;
      }
      if (action === "business") {
        state.score += 3;
        logAction("Commander requested business impact estimate", "Incident Commander");
        toast("Business impact requested", "Portal availability and support impact are now part of the decision record.");
        renderCommanderWarRoom();
        renderReportBuilder();
        return;
      }
      if (action === "support-watch") {
        state.supportComplaints += 1;
        logAction("Commander asked Support to monitor profile-data complaints", "Incident Commander");
        toast("Support monitoring active", "Customer-impact updates will be easier to interpret.");
        renderCommanderWarRoom();
        return;
      }
      if (action === "authorizeRecovery") {
        if (!state.patchDeployed || state.monitoringStableSince === null) {
          toast("Recovery not ready", "Wait for deployment and a stable monitoring window.", "bad");
          return;
        }
        state.recoveryAuthorized = true;
        if (state.incidentClock.recoveredAt === null) state.incidentClock.recoveredAt = state.elapsedSeconds;
        logAction("Commander authorized recovery after production validation", "Incident Commander");
        toast("Recovery authorized", "Production validation and monitoring window are accepted.");
        renderCommanderWarRoom();
        renderReportBuilder();
        renderMetrics();
        return;
      }
      if (!commandReady() && ["accept", "targeted", "blockip", "wait", "isolate"].includes(action)) {
        toast("No command action yet", "Commander can monitor context, but SOC has not escalated an evidence-backed handoff.", "bad");
        return;
      }
      if (!state.commanderAccepted && ["targeted", "blockip", "wait", "isolate"].includes(action)) {
        toast("Accept command first", "A containment decision requires command ownership.", "bad");
        return;
      }
      if (action === "accept") {
        markHandoffViewed("commander");
        state.commanderAccepted = true;
        state.score += 8;
        logAction("Incident command accepted", state.user ? state.user.name + " / Commander" : "Incident Commander");
        toast("Command accepted", "Incident Commander owns cross-team coordination.");
      }
      if (action === "more") {
        state.evidence = clamp(state.evidence + 8, 0, 100);
        state.attackerProgress = clamp(state.attackerProgress + 5, 0, 100);
        state.attackerHold = Math.max(state.attackerHold, 20);
        logAction("Requested additional DB and egress evidence", "Incident Commander");
        toast("More evidence requested", "Evidence improves, but attacker gets more time.", "bad");
      }
      if (action === "targeted") {
        state.commandDecision = "targeted containment";
        state.risk = clamp(state.risk - 18, 0, 100);
        state.serviceHealth = clamp(state.serviceHealth - 8, 0, 100);
        state.containmentTime = state.elapsedSeconds;
        if (state.incidentClock.containedAt === null) state.incidentClock.containedAt = state.elapsedSeconds;
        state.appliedRecs.contain = true;
        updateHandoff("appsec", "Commander assigned AppSec to reproduce, patch, test, and request deployment.");
        updateHandoff("legal", "Commander requested legal assessment based on confirmed DB access and customer impact.");
        logAction(`Approved targeted containment with ${Math.round(commanderConfidence())}% confidence`, "Incident Commander");
        toast("Containment approved", "Security improves with limited customer disruption.");
      }
      if (action === "isolate") {
        state.commandDecision = "full isolation";
        state.risk = clamp(state.risk - 30, 0, 100);
        state.serviceHealth = clamp(state.serviceHealth - 55, 0, 100);
        state.loss += 90000;
        state.containmentTime = state.elapsedSeconds;
        if (state.incidentClock.containedAt === null) state.incidentClock.containedAt = state.elapsedSeconds;
        logAction("Approved full customer portal isolation", "Incident Commander");
        toast("Portal isolated", "Security improves sharply, but business impact rises.", "bad");
      }
      if (action === "blockip") {
        state.commandDecision = "block source IP only";
        state.risk = clamp(state.risk - 6, 0, 100);
        state.attackerProgress = clamp(state.attackerProgress + 9, 0, 100);
        state.score -= 7;
        logAction("Blocked only source IP 198.51.100.24; bypass risk remains", "Incident Commander");
        toast("Partial containment", "One source is blocked, but the vulnerable endpoint remains exploitable.", "bad");
      }
      if (action === "wait") {
        state.commandDecision = "continue monitoring";
        state.evidence = clamp(state.evidence + 4, 0, 100);
        state.risk = clamp(state.risk + 10, 0, 100);
        state.attackerProgress = clamp(state.attackerProgress + 14, 0, 100);
        state.loss += 22000;
        state.score -= 10;
        logAction("Continued monitoring without containment; attacker momentum increased", "Incident Commander");
        toast("Containment delayed", "Evidence improves slightly, but risk and impact rise.", "bad");
      }
      renderMetrics();
      renderApprovals();
      renderCommanderWarRoom();
      renderReportBuilder();
    }

    function renderTerminal() {
      els.socTerminalOutput.textContent = state.terminalLines.slice(-16).join("\n");
      els.socTerminalOutput.scrollTop = els.socTerminalOutput.scrollHeight;
    }

    function runSocCommand(raw) {
      const command = raw.trim().toLowerCase();
      if (!command) return;
      state.terminalLines.push(`analyst@soc> ${raw}`);
      logAction(`SOC terminal command: ${raw}`);
      if (command === "help") {
        state.terminalLines.push("commands: timeline | search ip 198.51.100.24 | search user admin | block 198.51.100.24 | isolate web-01 | snapshot db");
      } else if (command === "timeline") {
        state.terminalLines.push("09:12 WAF alert\n09:14 admin route probing\n09:17 SQLi payload succeeds\n09:20 users table queried\n09:27 possible admin login\n09:31 export attempt");
        state.evidence = clamp(state.evidence + 5, 0, 100);
        state.attackerHold = Math.max(state.attackerHold, 20);
      } else if (command.includes("search ip")) {
        state.terminalLines.push("12 events found for 198.51.100.24\n09:04 GET /customers?id=12\n09:06 SQL error on id parameter\n09:12 SQLI_GENERIC_17\n09:20 users table query correlated");
        state.evidence = clamp(state.evidence + 8, 0, 100);
        state.attackerHold = Math.max(state.attackerHold, 25);
      } else if (command.includes("search user admin")) {
        state.terminalLines.push("admin: no confirmed compromise\nwarning: failed login attempts from new ASN after DB scan");
        state.evidence = clamp(state.evidence + 4, 0, 100);
      } else if (command.includes("block")) {
        state.terminalLines.push("WAF rule promoted to BLOCK for source and SQLi pattern\nattacker switches IP but payload path is disrupted");
        state.risk = clamp(state.risk - 10, 0, 100);
        state.attackerHold = Math.max(state.attackerHold, 50);
        state.containmentTime = state.elapsedSeconds;
        state.score += 8;
      } else if (command.includes("isolate")) {
        state.terminalLines.push("web-01 isolation staged\nbusiness warning: customer portal may degrade");
        state.risk = clamp(state.risk - 12, 0, 100);
        state.loss += 18000;
        state.serviceHealth = clamp(state.serviceHealth - 12, 0, 100);
        state.containmentTime = state.elapsedSeconds;
      } else if (command.includes("snapshot")) {
        state.terminalLines.push("DB audit snapshot acquired\nsha256=92fc3b71d0e... source=db-prod-01 collector=SOC");
        state.evidence = clamp(state.evidence + 14, 0, 100);
        state.attackerHold = Math.max(state.attackerHold, 30);
        state.score += 6;
      } else {
        state.terminalLines.push("unknown command. type 'help'");
      }
      renderTerminal();
      renderMetrics();
      renderImpactMonitor();
      renderReportBuilder();
      renderObjective();
    }

    function renderEvidenceGame() {
      if (!els.evidenceLogRows) return;
      if (state.role === "AppSec Engineer") {
        const chain = [
          ["HTTP payload", state.appsecExploitReproduced, "GET /customers?id=12' UNION SELECT email,password_hash FROM users--"],
          ["Application trace", state.appsecTraceInspected, "req.query.id → query string → db.query()"],
          ["Generated SQL", state.appsecRootCauseConfirmed, "SELECT * FROM customers WHERE id=12' UNION SELECT ..."],
          ["Code diff", state.appsecPatchApplied, "PATCH-204 replaces concatenation with bound parameter."],
          ["Regression results", state.patchTested, "Normal lookup, invalid ID, and SQLi payload tests passed."]
        ];
        els.evidenceLogRows.innerHTML = chain.map((item, index) => `<button class="log-row ${item[1] ? "collected" : "suspicious"}" type="button" data-appsec-evidence-step="${index}">
          ${item[0]} — ${item[2]}
        </button>`).join("");
        els.eventInspector.innerHTML = `<div class="report-section"><strong>AppSec Evidence Chain</strong><span>HTTP payload → application code → SQL query → code diff → regression tests.</span></div>
          <div class="ready-row ${state.appsecExploitReproduced ? "done" : ""}"><span>${state.appsecExploitReproduced ? "✓" : "?"}</span><span>Exploit reproduction evidence</span></div>
          <div class="ready-row ${state.appsecRootCauseConfirmed ? "done" : ""}"><span>${state.appsecRootCauseConfirmed ? "✓" : "?"}</span><span>Root cause evidence</span></div>
          <div class="ready-row ${state.patchTested ? "done" : ""}"><span>${state.patchTested ? "✓" : "?"}</span><span>Patch validation evidence</span></div>
          <div class="actions"><button class="btn primary" type="button" data-page-shortcut="appsec">Open remediation workflow</button><button class="btn" type="button" data-page-shortcut="reportbuilder">Open remediation report</button></div>`;
        els.collectedEvidenceList.innerHTML = chain.filter(item => item[1]).length
          ? chain.filter(item => item[1]).map(item => `<div class="ready-row done"><span>✓</span><span>${item[0]}: ${item[2]}</span></div>`).join("")
          : `<div class="ready-row"><span>?</span><span>No AppSec evidence generated yet. Start in the remediation workspace.</span></div>`;
        els.eventInspector.querySelectorAll("[data-page-shortcut]").forEach(button => button.addEventListener("click", () => showPage(button.dataset.pageShortcut)));
        return;
      }
      if (state.role === "Legal/Compliance") {
        const chain = [
          ["Security incident", true, "Customer portal SQL injection under legal review."],
          ["Personal data involved", Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]).length >= 3, "Data classes selected in assessment."],
          ["Exposure assessment", state.legalExposureSaved, "Access likelihood, subjects affected, risk to individuals."],
          ["Notification threshold", state.legalDecisionRecorded, "Authority/data subject posture documented."],
          ["Communication approval", Object.keys(state.legalComms).length >= 2, "External/internal wording reviewed."],
          ["Legal decision", state.reportReadiness >= 85, "Compliance report ready."]
        ];
        els.evidenceLogRows.innerHTML = chain.map(item => `<button class="log-row ${item[1] ? "collected" : "suspicious"}" type="button">${item[0]} — ${item[2]}</button>`).join("");
        els.eventInspector.innerHTML = `<div class="report-section"><strong>Compliance Decision Chain</strong><span>Security incident → personal data involved → exposure assessment → risk to individuals → notification threshold → legal decision → communication approval.</span></div>
          ${chain.map(item => `<div class="ready-row ${item[1] ? "done" : ""}"><span>${item[1] ? "✓" : "?"}</span><span>${item[0]}</span></div>`).join("")}
          <div class="actions"><button class="btn primary" type="button" data-page-shortcut="legal">Open assessment</button><button class="btn" type="button" data-page-shortcut="reportbuilder">Open compliance report</button></div>`;
        els.collectedEvidenceList.innerHTML = chain.filter(item => item[1]).map(item => `<div class="ready-row done"><span>✓</span><span>${item[0]} preserved in legal record</span></div>`).join("") || `<div class="ready-row"><span>?</span><span>No compliance decision evidence preserved yet.</span></div>`;
        els.eventInspector.querySelectorAll("[data-page-shortcut]").forEach(button => button.addEventListener("click", () => showPage(button.dataset.pageShortcut)));
        return;
      }
      const visibleRows = evidenceGameRows.filter(row => state.evidenceFilter === "all" || row.ip === state.evidenceFilter || row.source === state.evidenceFilter);
      els.evidenceLogRows.innerHTML = `<button class="log-row ${state.evidenceFilter === "all" ? "collected" : ""}" type="button" data-evidence-filter="all">Show all log events</button>` + visibleRows.map(row => `<button class="log-row ${row.suspicious ? "suspicious" : ""} ${state.collectedEvidence[row.id] ? "collected" : ""} ${state.highlightEvidenceId === row.id ? "highlight" : ""}" type="button" data-evidence-row="${row.id}">
        ${row.text}
      </button>`).join("");
      els.evidenceLogRows.querySelectorAll("[data-evidence-filter]").forEach(button => button.addEventListener("click", () => {
        state.evidenceFilter = button.dataset.evidenceFilter;
        renderEvidenceGame();
      }));
      els.evidenceLogRows.querySelectorAll("button").forEach(button => {
        if (!button.dataset.evidenceRow) return;
        button.addEventListener("click", () => inspectEvidenceRow(button.dataset.evidenceRow));
        button.addEventListener("contextmenu", event => {
          event.preventDefault();
          showContextMenu(event.clientX, event.clientY, button.dataset.evidenceRow);
        });
      });
      const collected = evidenceGameRows.filter(row => state.collectedEvidence[row.id]);
      els.collectedEvidenceList.innerHTML = collected.length ? collected.map(row => `<div class="ready-row done"><span>✓</span><span>${row.id} ${row.source}: ${row.text}</span></div>`).join("") : `<div class="ready-row"><span>?</span><span>No evidence collected yet.</span></div>`;
      renderCollectedEvidenceCards(collected);
      renderEventInspector();
    }

    function inspectEvidenceRow(id) {
      state.selectedEvidenceRow = id;
      renderEventInspector();
    }

    function renderCollectedEvidenceCards(collected) {
      if (!els.collectedEvidenceList || !collected.length) return;
      els.collectedEvidenceList.innerHTML = collected.map(row => `<div class="custody-card">
        <strong>${row.id} ${row.source} Evidence</strong>
        <span>Confidence: ${row.confidence} | Collected ${row.time} | Integrity: SHA-256 verified</span>
        <span>Collected by: ${state.user ? state.user.name : state.role} | Source: ${row.sourceHost}</span>
        <span>${state.evidenceNotes[row.id] || row.details}</span>
        <div class="custody-actions">
          <button class="btn" type="button" data-view-evidence="${row.id}">View</button>
          <button class="btn" type="button" data-note-evidence="${row.id}">Add note</button>
          <button class="btn ghost" type="button" data-remove-evidence="${row.id}">Remove</button>
        </div>
      </div>`).join("");
      els.collectedEvidenceList.querySelectorAll("[data-view-evidence]").forEach(button => button.addEventListener("click", () => inspectEvidenceRow(button.dataset.viewEvidence)));
      els.collectedEvidenceList.querySelectorAll("[data-note-evidence]").forEach(button => button.addEventListener("click", () => {
        state.evidenceNotes[button.dataset.noteEvidence] = "Analyst note: related to SQLi incident timeline and preserved for final report.";
        logAction(`Analyst note added to ${button.dataset.noteEvidence}`);
        renderEvidenceGame();
        renderReportBuilder();
      }));
      els.collectedEvidenceList.querySelectorAll("[data-remove-evidence]").forEach(button => button.addEventListener("click", () => {
        delete state.collectedEvidence[button.dataset.removeEvidence];
        logAction(`Evidence removed from case: ${button.dataset.removeEvidence}`);
        renderEvidenceGame();
        renderReportBuilder();
      }));
    }

    function renderEventInspector() {
      if (!els.eventInspector) return;
      const row = evidenceGameRows.find(item => item.id === state.selectedEvidenceRow);
      if (!row) {
        els.eventInspector.innerHTML = `<div class="ready-row"><span>?</span><span>Select a log event to inspect indicators and actions.</span></div>`;
        return;
      }
      const score = row.suspicious ? 87 : 18;
      els.eventInspector.innerHTML = `
        <div class="report-section"><strong>${row.id} / ${row.source}</strong><span>${row.text}</span></div>
        <div class="report-section"><strong>Event facts</strong><span>Source IP: ${row.ip} | Host: ${row.sourceHost} | Time: ${row.time} | Related events: ${evidenceGameRows.filter(item => item.ip === row.ip && item.id !== row.id).length}</span></div>
        <div class="report-section"><strong>Analyst interpretation</strong><span>${row.details}</span></div>
        <div class="ready-row ${row.suspicious ? "done" : ""}"><span>${row.suspicious ? "✓" : "?"}</span><span>Suspicion score: ${score}%</span></div>
        <button class="btn primary" type="button" data-inspector-action="add">Add to case</button>
        <button class="btn" type="button" data-inspector-action="ip">Pivot on IP</button>
        <button class="btn" type="button" data-inspector-action="db">Search database activity</button>
        <button class="btn ghost" type="button" data-inspector-action="dismiss">Mark irrelevant</button>`;
      els.eventInspector.querySelectorAll("[data-inspector-action]").forEach(button => button.addEventListener("click", () => {
        const action = button.dataset.inspectorAction;
        if (action === "add") collectEvidence(row.id);
        if (action === "ip") {
          state.evidenceFilter = row.ip;
          logAction(`Pivoted Evidence Center on IP ${row.ip}`);
          runSocCommand(`search ip ${row.ip}`);
          showPivotResults(row, "ip");
          renderEvidenceGame();
        }
        if (action === "db") {
          state.evidence = clamp(state.evidence + 6, 0, 100);
          state.selectedEvidenceRow = "E-005";
          state.evidenceFilter = "DB";
          logAction("Searched DB activity related to exploit request");
          toast("Database pivot complete", "DB-8841 correlated with HTTP request. Evidence +6%");
          showPivotResults(row, "db");
          renderEvidenceGame();
          renderMetrics();
        }
        if (action === "dismiss") {
          state.attackerProgress = clamp(state.attackerProgress + 4, 0, 100);
          toast("Event dismissed", "If this was relevant, attacker progress continues.", "bad");
          renderMetrics();
        }
      }));
    }

    function showPivotResults(row, type) {
      if (type === "db") {
        openDrawer("Database Activity Results", `<div class="report-section"><strong>Correlation</strong><span>${row.id} → DB-8841</span></div>
          <div class="report-section"><strong>Query actor</strong><span>web_portal_ro via customer-portal-prod</span></div>
          <div class="report-section"><strong>Tables touched</strong><span>users, customers</span></div>
          <div class="report-section"><strong>Records accessed</strong><span>247 customer records; external exfiltration not established</span></div>
          <div class="report-section"><strong>Suspicious query</strong><span>SELECT email,password_hash FROM users through injected customer id parameter</span></div>
          <div class="actions"><button class="btn primary" type="button" data-pivot-add="E-005">Add DB evidence</button><button class="btn" type="button" data-pivot-add="E-008">Check customer impact</button></div>`);
      } else {
        openDrawer("IP Pivot Results", `<div class="report-section"><strong>Source</strong><span>${row.ip}</span></div>
          <div class="report-section"><strong>HTTP requests</strong><span>17 requests in 9 minutes</span></div>
          <div class="report-section"><strong>Routes touched</strong><span>/customers → /admin/export → /customers?id=12 UNION SELECT</span></div>
          <div class="report-section"><strong>Related events</strong><span>WAF-1192, HTTP-8841, DB-8841, NET-4432</span></div>
          <div class="report-section"><strong>Customer-impact signal</strong><span>09:19:22 support reports profile-data mix-up; no outbound dump confirmed</span></div>
          <div class="actions"><button class="btn primary" type="button" data-pivot-add="E-003">Add HTTP exploit</button><button class="btn" type="button" data-pivot-add="E-004">Add WAF alert</button><button class="btn" type="button" data-pivot-add="E-008">Add customer impact</button></div>`);
      }
      document.querySelectorAll("[data-pivot-add]").forEach(button => button.addEventListener("click", () => {
        collectEvidence(button.dataset.pivotAdd);
        els.eventDrawer.classList.remove("open");
      }));
    }

    function inboxRiskMeta(severity) {
      const level = String(severity || "LOW").toUpperCase();
      if (level === "HIGH") return { className: "risk-high", label: "High risk", score: 86 };
      if (level === "MEDIUM") return { className: "risk-medium", label: "Medium risk", score: 58 };
      return { className: "risk-low", label: "Low risk", score: 24 };
    }

    function inboxStatusClass(status) {
      return `status-${String(status || "NEW").toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    }

    function renderRiskListRow({ id, time, source, title, asset, detail, status, risk, selected = false, actionLabel = "Review", dataName }) {
      return `<button class="inbox-alert ${risk.className} ${selected ? "active" : ""}" type="button" ${dataName}="${id}" data-risk="${risk.label}">
        <span class="inbox-time">${time}</span>
        <span class="inbox-content">
          <span class="inbox-title-row"><b>${title}</b><span class="risk-badge">${risk.label}</span><span class="status-badge ${inboxStatusClass(status)}">${status}</span></span>
          <span class="inbox-meta"><span>${source}</span><span>${asset}</span></span>
          <span class="inbox-detail">${detail}</span>
        </span>
        <span class="inbox-row-action">${actionLabel}</span>
      </button>`;
    }

    function renderSocInbox() {
      if (!els.socInbox) return;
      els.socInbox.className = "inbox-list";
      if (state.role === "Incident Commander") {
        renderCommanderUpdates();
        return;
      }
      const sortedAlerts = [...inboxAlerts].sort((a, b) => inboxRiskMeta(b.sev).score - inboxRiskMeta(a.sev).score);
      els.socInbox.innerHTML = sortedAlerts.map(alert => {
        const risk = inboxRiskMeta(alert.sev);
        const status = state.inboxStatuses[alert.id] || "NEW";
        return renderRiskListRow({
          id: alert.id,
          time: alert.timestamp,
          source: alert.rule,
          title: alert.title,
          asset: alert.asset,
          detail: alert.detail,
          status,
          risk,
          selected: state.selectedInbox === alert.id,
          actionLabel: "Open",
          dataName: "data-alert"
        });
      }).join("");
      els.socInbox.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => {
          const alert = inboxAlerts.find(item => item.id === button.dataset.alert);
          const risk = inboxRiskMeta(alert.sev);
          const status = state.inboxStatuses[alert.id] || "NEW";
          state.selectedInbox = alert.id;
          openDrawer(`${alert.title}`, `<div class="inbox-drawer-summary ${risk.className}">
              <span class="risk-badge">${risk.label}</span>
              <span class="status-badge ${inboxStatusClass(status)}">${status}</span>
              <strong>${alert.asset}</strong>
              <span>${alert.detail}</span>
            </div>
            <div class="report-section"><strong>Status</strong><span>${status}</span></div>
            <div class="report-section"><strong>Source IP</strong><span>${alert.sourceIp}</span></div>
            <div class="report-section"><strong>Destination</strong><span>${alert.destination}</span></div>
            <div class="report-section"><strong>Rule</strong><span>${alert.rule}</span></div>
            <div class="report-section"><strong>Timestamp</strong><span>${alert.timestamp}</span></div>
            <div class="report-section"><strong>HTTP/request detail</strong><span>${alert.request}</span></div>
            <div class="report-section"><strong>Related events</strong><span>${alert.related.join("<br>")}</span></div>
            <p class="small">${alert.detail}</p>
            <div class="actions">
              <button class="btn" data-inbox-action="assign" type="button">Assign to me</button>
              <button class="btn primary" data-inbox-action="investigate" type="button">Investigate</button>
              <button class="btn" data-inbox-action="dismiss" type="button">Dismiss as false positive</button>
              <button class="btn" data-inbox-action="escalate" type="button">Escalate</button>
              <button class="btn ghost" data-inbox-action="resolve" type="button">Resolve</button>
            </div>`);
          document.querySelectorAll("[data-inbox-action]").forEach(actionButton => actionButton.addEventListener("click", () => handleInboxAction(alert, actionButton.dataset.inboxAction)));
          renderSocInbox();
        });
      });
    }

    function renderCommanderUpdates() {
      const updates = [
        { time: "09:12", source: "SOC ANALYST", title: "Possible exploitation detected", status: `Confidence: ${Math.round(commanderConfidence())}%`, action: "View handoff", risk: "HIGH", detail: "WAF and DB signals indicate possible customer-portal exploitation." },
        { time: "09:15", source: "DATABASE TEAM", title: "Unusual read volume confirmed", status: "Impact assessment pending", action: "Request update", risk: "HIGH", detail: "Read volume exceeds baseline and may affect customer records." },
        { time: "09:17", source: "APPSEC", title: "Vulnerable endpoint identified", status: state.patchTested ? "Patch tested" : "Patch ETA: 12 minutes", action: "Assign owner", risk: "MEDIUM", detail: "Engineering has located the likely vulnerable route." },
        { time: "09:19", source: "CUSTOMER SUPPORT", title: "3 customer reports received", status: "Customer impact not confirmed", action: "Acknowledge", risk: "MEDIUM", detail: "Support reports may indicate customer-visible data exposure." }
      ];
      els.socInbox.className = "inbox-list";
      els.socInbox.innerHTML = updates.map((item, index) => renderRiskListRow({
        id: String(index),
        time: item.time,
        source: item.source,
        title: item.title,
        asset: item.status,
        detail: item.detail,
        status: item.action,
        risk: inboxRiskMeta(item.risk),
        actionLabel: "Open",
        dataName: "data-command-update"
      })).join("");
      els.socInbox.querySelectorAll("[data-command-update]").forEach(button => button.addEventListener("click", () => {
        const item = updates[Number(button.dataset.commandUpdate)];
        const risk = inboxRiskMeta(item.risk);
        openDrawer(`${item.source} update`, `<div class="inbox-drawer-summary ${risk.className}">
            <span class="risk-badge">${risk.label}</span>
            <span class="status-badge">${item.action}</span>
            <strong>${item.title}</strong>
            <span>${item.detail}</span>
          </div>
          <div class="report-section"><strong>Update</strong><span>${item.title}</span></div>
          <div class="report-section"><strong>Status</strong><span>${item.status}</span></div>
          <div class="actions">
            <button class="btn primary" type="button" data-update-action="ack">Acknowledge</button>
            <button class="btn" type="button" data-update-action="more">Request update</button>
            <button class="btn" type="button" data-update-action="owner">Assign owner</button>
          </div>`);
        document.querySelectorAll("[data-update-action]").forEach(actionButton => actionButton.addEventListener("click", () => {
          const action = actionButton.dataset.updateAction;
          logAction(`${action === "ack" ? "Acknowledged" : action === "more" ? "Requested update for" : "Assigned owner for"} ${item.source} handoff`, "Incident Commander");
          if (action === "more") state.evidence = clamp(state.evidence + 4, 0, 100);
          if (action === "owner") state.score += 4;
          els.eventDrawer.classList.remove("open");
          renderMetrics();
        }));
      }));
    }

    function handleInboxAction(alert, action) {
      if (action === "assign") {
        state.inboxStatuses[alert.id] = "ASSIGNED";
        logAction(`Assigned SOC alert to self: ${alert.title}`);
        if (alert.real && state.detectedTime === null) state.detectedTime = state.elapsedSeconds;
        if (alert.real && state.incidentClock.detectedAt === null) state.incidentClock.detectedAt = state.elapsedSeconds;
        if (alert.real && state.incidentClock.acknowledgedAt === null) state.incidentClock.acknowledgedAt = state.elapsedSeconds;
        toast("Alert assigned", `${alert.title} is now owned by ${state.user ? state.user.name : state.role}.`);
      }
      if (action === "investigate") {
        state.inboxStatuses[alert.id] = "INVESTIGATING";
        logAction(`Opened SOC alert: ${alert.title}`);
        if (alert.real && state.detectedTime === null) state.detectedTime = state.elapsedSeconds;
        if (alert.real && state.incidentClock.detectedAt === null) state.incidentClock.detectedAt = state.elapsedSeconds;
        if (alert.real) {
          state.score += 8;
          state.evidence = clamp(state.evidence + 6, 0, 100);
          state.attackerHold = Math.max(state.attackerHold, 25);
          toast("Correct alert selected", "WAF alert moved to INVESTIGATING. Evidence +6%");
          state.objectiveStep = Math.max(state.objectiveStep, 1);
        } else {
          state.attackerProgress = clamp(state.attackerProgress + 6, 0, 100);
          toast("False positive investigated", "Time spent here let attacker progress +6%.", "bad");
        }
      }
      if (action === "dismiss") {
        state.inboxStatuses[alert.id] = "DISMISSED";
        logAction(`Dismissed SOC alert: ${alert.title}`);
        toast(alert.real ? "Risky dismissal" : "False positive dismissed", alert.real ? "Real incident dismissed. Attacker progress +15%." : "Queue cleaned.", alert.real ? "bad" : "good");
        if (alert.real) state.attackerProgress = clamp(state.attackerProgress + 15, 0, 100);
      }
      if (action === "escalate") {
        if (alert.real && !socScoped()) {
          toast("Escalation blocked", "Collect HTTP, WAF, and DB evidence before handing off to Commander.", "bad");
          showPage("evidence");
          state.highlightEvidenceId = state.collectedEvidence["E-003"] ? state.collectedEvidence["E-004"] ? "E-005" : "E-004" : "E-003";
          renderEvidenceGame();
          return;
        }
        state.inboxStatuses[alert.id] = "ESCALATED";
        if (alert.real && state.incidentClock.escalatedAt === null) state.incidentClock.escalatedAt = state.elapsedSeconds;
        if (alert.real) updateHandoff("commander", `SOC escalation: confidence ${Math.round(commanderConfidence())}% | 247 records potentially accessed.`);
        state.approvals.push({ id: `APR-${String(42 + state.approvals.length).padStart(4, "0")}`, type: `${alert.title} escalation`, status: "pending", elapsed: 0, needsInfo: false, requester: state.user ? state.user.name : state.role, owner: "Incident Commander", evidenceAtRequest: state.evidence, reason: alert.detail });
        logAction(`Escalated SOC alert: ${alert.title}`);
        toast("Escalation created", "Incident Commander approval queue updated.");
      }
      if (action === "resolve") {
        state.inboxStatuses[alert.id] = "RESOLVED";
        logAction(`Resolved SOC alert: ${alert.title}`);
        toast("Alert resolved", "SOC inbox status updated.");
      }
      renderSocInbox();
      renderMetrics();
      renderObjective();
      renderApprovals();
    }

    function renderKillGame() {
      if (!els.killGameEvents) return;
      els.killGameEvents.innerHTML = killGameItems.map(item => `<button class="event-token ${state.selectedKillEvent === item.id ? "selected" : ""}" type="button" data-kill-event="${item.id}">${item.text}</button>`).join("");
      const phases = ["Recon", "Exploit", "Enumerate", "Contain", "Recover"];
      els.killGameBuckets.innerHTML = phases.map(phase => {
        const assigned = killGameItems.filter(item => state.killAssignments[item.id] === phase);
        const correct = assigned.length && assigned.every(item => item.phase === phase);
        return `<button class="phase-bucket ${correct ? "correct" : ""}" type="button" data-bucket="${phase}"><b>${phase}</b><br>${assigned.map(item => item.text).join("<br>") || "Drop selected event here"}</button>`;
      }).join("");
      els.killGameEvents.querySelectorAll("button").forEach(button => button.addEventListener("click", () => {
        state.selectedKillEvent = button.dataset.killEvent;
        renderKillGame();
      }));
      els.killGameBuckets.querySelectorAll("button").forEach(button => button.addEventListener("click", () => {
        if (!state.selectedKillEvent) return;
        state.killAssignments[state.selectedKillEvent] = button.dataset.bucket;
        state.selectedKillEvent = null;
        const correctCount = killGameItems.filter(item => state.killAssignments[item.id] === item.phase).length;
        els.killGameStatus.textContent = `Attack path confidence: ${correctCount * 20}%`;
        if (correctCount === killGameItems.length) {
          state.evidence = clamp(state.evidence + 15, 0, 100);
          state.score += 20;
        }
        renderKillGame();
        renderMetrics();
      }));
    }

    function renderAppSec() {
      if (!els.appsecCode) return;
      if (!appsecReady() && !state.appsecHandoffAccepted) {
        if (els.appsecHandoff) els.appsecHandoff.innerHTML = `
          <div class="ready-row"><span>•</span><span><strong>AppSec Status:</strong> STANDBY</span></div>
          <div class="ready-row"><span>•</span><span><strong>Incident:</strong> INC-2026-0812</span></div>
          <div class="ready-row"><span>•</span><span><strong>Known technical signal:</strong> suspicious activity on /customers</span></div>
          <div class="ready-row"><span>•</span><span><strong>SOC validation:</strong> ${socScoped() ? "SCOPED" : socValidated() ? "IN PROGRESS" : "PENDING"}</span></div>
          <div class="ready-row"><span>?</span><span><strong>Assigned remediation:</strong> NONE</span></div>`;
        if (els.acceptAppsecHandoffBtn) {
          els.acceptAppsecHandoffBtn.disabled = true;
          els.acceptAppsecHandoffBtn.textContent = "No active handoff";
        }
        if (els.reproLab) {
          els.reproLab.innerHTML = `<div class="ready-row"><span>?</span><span>No active handoff. You can review public incident context, but reproduction requires assignment.</span></div>
            <div class="actions"><button class="btn" type="button" data-appsec-standby="context">Review public incident context</button><button class="btn" type="button" data-appsec-standby="asset">Inspect app ownership/build</button><button class="btn" type="button" data-appsec-standby="soc">Ask SOC for technical evidence</button></div>`;
          els.reproLab.querySelectorAll("[data-appsec-standby]").forEach(button => button.addEventListener("click", () => {
            const action = button.dataset.appsecStandby;
            if (action === "context") logAction("AppSec reviewed public incident context", "AppSec Engineer");
            if (action === "asset") logAction("AppSec checked customer-portal-prod ownership and current build", "AppSec Engineer");
            if (action === "soc") {
              updateHandoff("appsec", "AppSec requested WAF/HTTP/DB artifacts before remediation assignment.");
              logAction("AppSec requested technical evidence from SOC", "AppSec Engineer");
            }
            toast("AppSec standby activity", "Context captured without starting remediation prematurely.");
            renderRecentActions();
          }));
        }
        if (els.appsecCode) els.appsecCode.textContent = "Read-only context: affected application is customer-portal-prod / GET /customers?id=. Code inspection unlocks after AppSec handoff.";
        if (els.patchBuilder) els.patchBuilder.innerHTML = `<div class="ready-row"><span>?</span><span>Patch actions gated until exploit reproduction and root cause confirmation.</span></div>`;
        if (els.appsecTests) els.appsecTests.innerHTML = `<div class="ready-row"><span>?</span><span>Validation loop gated until a patch exists.</span></div>`;
        return;
      }
      const appsecResidualRisk = state.patchDeployed ? "VERY LOW" : state.patchTested && state.appsecPatchApplied ? "LOW" : state.appsecPatchApplied ? "MEDIUM" : "HIGH";
      const appsecDeploymentStatus = state.patchDeployed ? "APPROVED" : state.appsecDeploymentRequested ? "PENDING COMMANDER APPROVAL" : "NOT REQUESTED";
      if (els.appsecMetrics) {
        els.appsecMetrics.innerHTML = [
          ["Vulnerability", "SQL Injection"],
          ["Endpoint", "/customers"],
          ["Exploitability", state.appsecExploitReproduced ? "CONFIRMED" : "HIGH"],
          ["Root cause", state.appsecRootCauseConfirmed ? "CONFIRMED" : "NOT VALIDATED"],
          ["Patch status", state.appsecPatchApplied ? "READY" : "NOT STARTED"],
          ["Tests", state.patchTested ? "3 / 3 PASSED" : "0 / 3"],
          ["Deployment", appsecDeploymentStatus],
          ["Residual risk", appsecResidualRisk]
        ].map(item => `<div class="card metric"><span class="small">${item[0]}</span><strong>${item[1]}</strong></div>`).join("");
      }
      if (els.appsecWarRoomSummary) {
        els.appsecWarRoomSummary.innerHTML = [
          ["SOC finding", "Suspected SQLi on /customers?id="],
          ["AppSec mission", "Reproduce → root cause → patch → tests → deployment request"],
          ["Root cause", state.appsecRootCauseConfirmed ? "Confirmed in customerController.js:43" : "Needs code trace"],
          ["Patch", state.appsecPatchApplied ? "PATCH-204 ready" : "Not built"],
          ["Tests", state.patchTested ? "3/3 passed" : "Waiting"],
          ["Deployment", state.patchDeployed ? "Approved" : state.appsecDeploymentRequested ? "Pending Commander approval" : "Not requested"]
        ].map(item => `<div class="tradeoff-card"><b>${item[0]}</b><span class="small">${item[1]}</span></div>`).join("");
      }
        if (els.appsecHandoff) {
        els.appsecHandoff.innerHTML = [
          ["Handoff version", handoffLine("appsec")],
          ["Finding", "Suspected SQL injection"],
          ["Affected endpoint", "GET /customers?id="],
          ["Source", "198.51.100.24"],
          ["Observed payload", "12' UNION SELECT email,password_hash FROM users--"],
          ["SOC confidence", `${Math.round(commanderConfidence())}%`],
          ["Evidence attached", "WAF-1192, HTTP-8841, DB-8841"],
          ["Requested action", "Reproduce exploit, identify root cause, prepare remediation"],
          ["Handoff status", state.appsecHandoffAccepted ? "Handoff accepted ✓" : "Awaiting AppSec acceptance"]
        ].map(item => `<div class="ready-row ${item[0] === "Handoff status" && state.appsecHandoffAccepted ? "done" : ""}"><span>${item[0] === "Handoff status" && state.appsecHandoffAccepted ? "✓" : "•"}</span><span><strong>${item[0]}:</strong> ${item[1]}</span></div>`).join("");
      }
      if (els.acceptAppsecHandoffBtn) {
        els.acceptAppsecHandoffBtn.textContent = state.appsecHandoffAccepted ? "Handoff accepted ✓" : "Accept handoff";
        els.acceptAppsecHandoffBtn.disabled = state.appsecHandoffAccepted;
      }
      if (els.confirmRootCauseBtn) els.confirmRootCauseBtn.disabled = !state.appsecTraceInspected || state.appsecRootCauseConfirmed;
      if (els.applyPatchBtn) els.applyPatchBtn.disabled = !state.appsecRootCauseConfirmed || state.appsecPatchApplied;
      if (els.testPatchBtn) els.testPatchBtn.disabled = !state.appsecPatchApplied || state.patchTested;
      if (els.deployPatchBtn) {
        els.deployPatchBtn.disabled = !state.patchTested || state.appsecDeploymentRequested || state.patchDeployed;
        els.deployPatchBtn.textContent = state.patchDeployed ? "Deployment approved ✓" : state.appsecDeploymentRequested ? "Pending Commander approval" : "Request deployment";
      }
      if (els.appsecRepro) {
        els.appsecRepro.innerHTML = `<div class="appsec-repro-grid">
          <div class="appsec-repro-card ${state.appsecBaselineRun ? "good" : ""}"><span class="small">Baseline response</span><strong>${state.appsecBaselineRun ? "200 OK" : "Not run"}</strong><span>GET /customers?id=12</span><span class="small">${state.appsecBaselineRun ? "11.2 KB | 1 customer row" : "Capture normal behavior first."}</span></div>
          <div class="appsec-repro-card ${state.appsecExploitReproduced ? "warn" : ""}"><span class="small">Injected response</span><strong>${state.appsecExploitReproduced ? "200 OK" : "Waiting"}</strong><span>12' UNION SELECT ...</span><span class="small">${state.appsecExploitReproduced ? "48.2 KB | suspicious data shape" : "Run safely in lab."}</span></div>
          <div class="appsec-repro-card ${state.appsecExploitReproduced ? "warn" : ""}"><span class="small">Response delta</span><strong>${state.appsecExploitReproduced ? "+4.8 KB" : "--"}</strong><span class="small">${state.appsecExploitReproduced ? "Payload changes response size significantly." : "No comparison yet."}</span></div>
          <div class="appsec-repro-card ${state.appsecExploitReproduced ? "warn" : ""}"><span class="small">DB anomaly</span><strong>${state.appsecExploitReproduced ? "Detected" : "--"}</strong><span class="small">${state.appsecExploitReproduced ? "web_portal_ro query pattern changed." : "Awaiting injected run."}</span></div>
        </div>`;
      }
      els.appsecCode.textContent = state.appsecPatchApplied ?
        `controllers/customerController.js

40 | async function getCustomer(req, res) {
41 |   const id = req.query.id;
42 |   const query =
43 |     "SELECT * FROM customers WHERE id = ?";
44 |
45 |   const rows = await db.execute(query, [id]);
46 |   return res.json(rows);
47 | }

Patch: parameterized query with bound id parameter.` :
        `controllers/customerController.js

40 | async function getCustomer(req, res) {
41 |   const id = req.query.id;
42 |   const query =
43 |     "SELECT * FROM customers WHERE id=" + id;
44 |
45 |   const rows = await db.query(query);
46 |   return res.json(rows);
47 | }

${state.appsecTraceInspected ? "Trace: req.query.id -> query string -> db.query()\nWarning: user-controlled input reaches SQL execution." : "Click Inspect code to trace user input to SQL execution."}
${state.appsecRootCauseConfirmed ? "ROOT CAUSE CONFIRMED: dynamic SQL construction without parameterization." : ""}`;
      if (els.patchBuilder) {
        const patches = [
          ["validation", "Input validation only", "Reject non-numeric IDs, but root cause may remain in other paths."],
          ["parameterized", "Parameterized query", "Bind user input as a parameter before SQL execution."],
          ["waf", "Block payload pattern", "Compensating control only; root cause remains exploitable."]
        ];
        els.patchBuilder.innerHTML = patches.map(item => `<button class="evidence-pick ${state.appsecSelectedPatch === item[0] ? "active" : ""}" type="button" data-appsec-patch="${item[0]}"><b>${item[1]}</b><span>${item[2]}</span></button>`).join("");
        els.patchBuilder.querySelectorAll("[data-appsec-patch]").forEach(button => button.addEventListener("click", () => {
          state.appsecSelectedPatch = button.dataset.appsecPatch;
          if (state.appsecSelectedPatch === "waf") toast("Compensating control only", "Root cause remains exploitable until the code uses parameterization.", "bad");
          if (state.appsecSelectedPatch === "validation") toast("Partial mitigation", "Validation helps, but parameterization is still required.", "bad");
          renderAppSec();
        }));
      }
      els.appsecTests.innerHTML = [
        ["Normal customer lookup", state.patchTested],
        ["Invalid ID rejected", state.patchTested],
        ["SQL injection payload blocked", state.patchTested],
        ["Authorization behavior preserved", state.patchTested],
        ["Deployment request sent", state.appsecDeploymentRequested || state.patchDeployed]
      ].map(item => `<div class="ready-row ${item[1] ? "done" : ""}"><span>${item[1] ? "✓" : "?"}</span><span>${item[0]}</span></div>`).join("");
      if (els.deploymentPackage) {
        els.deploymentPackage.innerHTML = [
          ...(state.patchDeployed ? [["✓ REMEDIATION COMPLETE", "Exploit no longer reproducible | 3/3 tests passed | Deployment approved | Residual risk: VERY LOW"]] : []),
          ["Patch", state.appsecPatchApplied ? "PATCH-204 parameterized query" : "Not created"],
          ["Endpoint", "/customers"],
          ["Tests", state.patchTested ? "3/3 passed" : "Blocked until tests pass"],
          ["Residual risk", appsecResidualRisk],
          ["Approval", state.patchDeployed ? "Commander approved" : state.appsecDeploymentRequested ? "Awaiting Incident Commander" : "Not requested"],
          ["Verify fix", state.patchDeployed ? "Exploit no longer reproducible" : "Awaiting deployment approval"],
          ["Normal traffic", state.patchDeployed ? "Preserved" : state.patchTested ? "Validated in test" : "Not verified"],
          ["Remediation", state.patchDeployed ? "Remediation complete ✓" : "Incomplete"]
        ].map(item => item[0].includes("REMEDIATION COMPLETE")
          ? `<div class="success-banner"><strong>${item[0]}</strong><span>${item[1]}</span></div>`
          : `<div class="ready-row ${item[1].includes("passed") || item[1].includes("LOW") || item[1].includes("approved") || item[1].includes("no longer") || item[1].includes("Preserved") || item[1].includes("complete") ? "done" : ""}"><span>${item[1].includes("Blocked") || item[1].includes("Not") || item[1].includes("Awaiting") || item[1].includes("Incomplete") ? "?" : "✓"}</span><span><strong>${item[0]}:</strong> ${item[1]}</span></div>`).join("");
      }
    }

    function renderLegal() {
      if (!els.legalFacts) return;
      if (!legalReady() && !state.legalHandoffAccepted) {
        if (els.legalHandoff) els.legalHandoff.innerHTML = `
          <div class="ready-row"><span>•</span><span><strong>Legal / Compliance:</strong> MONITORING</span></div>
          <div class="ready-row"><span>?</span><span><strong>Personal data involvement:</strong> UNKNOWN</span></div>
          <div class="ready-row"><span>?</span><span><strong>Confirmed affected subjects:</strong> UNKNOWN</span></div>
          <div class="ready-row"><span>•</span><span><strong>External exfiltration:</strong> NOT ESTABLISHED</span></div>
          <div class="ready-row"><span>?</span><span><strong>Notification assessment:</strong> NOT READY</span></div>`;
        if (els.acceptLegalHandoffBtn) {
          els.acceptLegalHandoffBtn.disabled = true;
          els.acceptLegalHandoffBtn.textContent = "No active legal handoff";
        }
        if (els.regClock) els.regClock.textContent = "NOT STARTED";
        els.legalFacts.innerHTML = `<div class="ready-row"><span>?</span><span>Available context only. Role-specific legal actions require confirmed facts.</span></div>`;
        if (els.dataClassificationGrid) els.dataClassificationGrid.innerHTML = `<div class="role-locked">Data classification unavailable until SOC/Commander provide confirmed incident facts.</div>`;
        if (els.exposureAssessment) {
          els.exposureAssessment.innerHTML = `<div class="ready-row"><span>?</span><span>Exposure assessment pending confirmed scope.</span></div>
            <div class="actions"><button class="btn" type="button" data-legal-standby="pii">Monitor PII indicators</button><button class="btn" type="button" data-legal-standby="facts">Request confirmed facts</button><button class="btn" type="button" data-legal-standby="wording">Review safe holding language</button></div>`;
          els.exposureAssessment.querySelectorAll("[data-legal-standby]").forEach(button => button.addEventListener("click", () => {
            const action = button.dataset.legalStandby;
            if (action === "pii") logAction("Legal monitored for personal-data indicators", "Legal/Compliance");
            if (action === "facts") {
              updateHandoff("legal", "Legal requested confirmed data classes, affected subjects, and exfiltration status.");
              logAction("Legal requested confirmed incident facts", "Legal/Compliance");
            }
            if (action === "wording") logAction("Legal reviewed preliminary holding-language constraints", "Legal/Compliance");
            toast("Legal monitoring activity", "Legal context captured without making a breach conclusion.");
            renderRecentActions();
          }));
        }
        if (els.notificationDecision) els.notificationDecision.innerHTML = `<div class="ready-row"><span>?</span><span>Notification decision pending evidence-backed facts.</span></div>`;
        return;
      }
      const selectedClasses = Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]);
      const evidenceSufficiency = state.legalDecisionRecorded ? "SUFFICIENT" : state.legalExposureSaved || selectedClasses.length >= 3 ? "PARTIAL" : "LOW";
      const personalDataStatus = selectedClasses.length >= 3 ? "CONFIRMED" : selectedClasses.length > 0 ? "POSSIBLE" : "UNKNOWN";
      const dataSubjectsEstimate = selectedClasses.length >= 4 ? "247 CONFIRMED" : selectedClasses.length >= 2 ? "124 EST." : "UNKNOWN";
      const thresholdStatus = state.legalDecisionRecorded ? "MET" : state.legalExposureSaved || selectedClasses.length >= 3 ? "LIKELY MET" : "NOT YET MET";
      const breachConfirmed = state.legalBreachStatus === "CONFIRMED";
      if (breachConfirmed && state.legalClockStartedAt === null) state.legalClockStartedAt = state.elapsedSeconds;
      const legalReviewComplete = state.legalDecisionRecorded && Object.keys(state.legalComms).length >= 2 && selectedClasses.length >= 3;
      const remaining = state.legalClockStartedAt === null ? null : Math.max(0, 72 * 3600 - (state.elapsedSeconds - state.legalClockStartedAt));
      const remainingText = remaining === null ? "NOT STARTED" : legalReviewComplete ? "COMPLETED" : `ACTIVE ${String(Math.floor(remaining / 3600)).padStart(2, "0")}:${String(Math.floor((remaining % 3600) / 60)).padStart(2, "0")}:${String(remaining % 60).padStart(2, "0")}`;
      if (els.complianceMetrics) {
        els.complianceMetrics.innerHTML = [
          ["Breach status", breachConfirmed ? "CONFIRMED" : "UNDER ASSESSMENT"],
          ["Personal data", personalDataStatus],
          ["Data subjects", state.legalExposureSaved ? "247 CONFIRMED" : dataSubjectsEstimate],
          ["Records accessed", state.recordsExposed === null ? "UNCONFIRMED" : state.recordsExposed.toLocaleString()],
          ["Notification", state.legalAuthorityNotification],
          ["Reg deadline", remainingText === "NOT STARTED" || remainingText === "COMPLETED" ? remainingText : remainingText.replace("ACTIVE ", "").slice(0, 5)],
          ["Evidence", evidenceSufficiency],
          ["Comms", Object.keys(state.legalComms).length >= 2 ? "REVIEWED" : state.legalComms.support ? "APPROVED" : "NOT APPROVED"]
        ].map(item => `<div class="card metric"><span class="small">${item[0]}</span><strong>${item[1]}</strong></div>`).join("");
      }
      if (els.legalHandoff) {
        els.legalHandoff.innerHTML = [
          ["Handoff version", handoffLine("legal")],
          ["Incident", "INC-2026-0812"],
          ["System", "Customer Portal"],
          ["Potential exposure", "Customer records"],
          ["Technical confidence", `${Math.round(commanderConfidence())}%`],
          ["Current legal status", breachConfirmed ? "CONFIRMED" : "UNDER ASSESSMENT"],
          ["Handoff", state.legalHandoffAccepted ? "Accepted ✓" : "Awaiting Legal/Compliance"]
        ].map(item => `<div class="ready-row ${item[1].includes("✓") ? "done" : ""}"><span>${item[1].includes("✓") ? "✓" : "•"}</span><span><strong>${item[0]}:</strong> ${item[1]}</span></div>`).join("");
      }
      if (els.acceptLegalHandoffBtn) {
        els.acceptLegalHandoffBtn.textContent = state.legalHandoffAccepted ? "Legal handoff accepted ✓" : "Accept legal handoff";
        els.acceptLegalHandoffBtn.disabled = state.legalHandoffAccepted;
      }
      els.regClock.textContent = remainingText;
      els.regClock.classList.toggle("active-clock", state.legalClockStartedAt !== null && !legalReviewComplete);
      els.legalFacts.innerHTML = [
        ["Customer portal affected", true],
        ["Personal data classified", selectedClasses.length >= 3],
        ["Exposure assessment saved", state.legalExposureSaved],
        ["Regulatory clock started", state.legalClockStartedAt !== null],
        ["Legal decision recorded", state.legalDecisionRecorded]
      ].map(item => `<div class="ready-row ${item[1] ? "done" : ""}"><span>${item[1] ? "✓" : "?"}</span><span>${item[0]}</span></div>`).join("");
      const classes = [
        ["name", "Name", true, "CONFIRMED"],
        ["email", "Email", true, "CONFIRMED"],
        ["phone", "Phone number", true, "POSSIBLE"],
        ["password", "Password hash", true, "CONFIRMED"],
        ["payment", "Payment data", false, "NOT EVIDENCED"],
        ["auth", "Authentication data", false, "NOT EVIDENCED"],
        ["special", "Special-category data", false, "NOT EVIDENCED"]
      ];
      if (els.dataClassificationGrid) {
        els.dataClassificationGrid.innerHTML = classes.map(item => {
          const selected = state.legalDataClasses[item[0]];
          const status = selected ? item[3] : "UNSELECTED";
          const badgeClass = status.toLowerCase().replace(/\s+/g, "-");
          const downstream = selected && item[2]
            ? "Updates personal-data status, subject estimate, and notification threshold."
            : selected
              ? "Marked as unsupported by current evidence."
              : "Click to classify";
          return `<button class="evidence-pick ${selected ? "active" : ""}" type="button" data-data-class="${item[0]}"><b>${item[1]}</b><span class="status-badge ${badgeClass}">${status}</span><span>${downstream}</span></button>`;
        }).join("");
        els.dataClassificationGrid.querySelectorAll("[data-data-class]").forEach(button => button.addEventListener("click", () => {
          state.legalDataClasses[button.dataset.dataClass] = !state.legalDataClasses[button.dataset.dataClass];
          const meta = classes.find(item => item[0] === button.dataset.dataClass);
          state.score += meta?.[2] ? 3 : -2;
          if (!meta?.[2]) toast("Not evidenced yet", `${meta[1]} is not supported by current evidence.`, "bad");
          renderLegal();
          renderPhases();
          renderReportBuilder();
        }));
      }
      if (els.exposureAssessment) {
        els.exposureAssessment.innerHTML = [
          ["Was personal data accessed?", state.legalExposureSaved ? "Likely" : personalDataStatus],
          ["Was external exfiltration confirmed?", "Not established"],
          ["Approx. data subjects", state.legalExposureSaved ? "247" : dataSubjectsEstimate],
          ["Notification threshold", thresholdStatus],
          ["Risk to individuals", state.legalRiskLevel === "PENDING" ? selectedClasses.length >= 3 ? "MODERATE likely" : "Medium pending review" : state.legalRiskLevel]
        ].map(item => `<div class="ready-row ${state.legalExposureSaved || item[1].includes("CONFIRMED") || item[1].includes("EST") || item[1].includes("MET") ? "done" : ""}"><span>${state.legalExposureSaved || item[1].includes("CONFIRMED") || item[1].includes("EST") || item[1].includes("MET") ? "✓" : "?"}</span><span><strong>${item[0]}</strong> ${item[1]}</span></div>`).join("");
      }
      if (els.notificationDecision) {
        const sufficiencyScore = state.legalDecisionRecorded ? 88 : state.legalExposureSaved ? 65 : selectedClasses.length ? 42 : 18;
        els.notificationDecision.innerHTML = [
          ["Evidence sufficiency", `${sufficiencyScore}%`],
          ["Notification threshold", thresholdStatus],
          ["Personal data breach", state.legalBreachStatus],
          ["Risk to rights/freedoms", state.legalRiskLevel],
          ["Authority notification", state.legalAuthorityNotification],
          ["Data subject notification", state.legalSubjectNotification]
        ].map(item => `<div class="ready-row ${!item[1].includes("PENDING") ? "done" : ""}"><span>${!item[1].includes("PENDING") ? "✓" : "?"}</span><span><strong>${item[0]}:</strong> ${item[1]}</span></div>`).join("");
      }
      if (els.notificationCenter) {
        els.notificationCenter.innerHTML = [
          ["Supervisory Authority", state.legalAuthorityNotification === "REQUIRED" ? "DRAFT REQUIRED" : "ASSESSMENT PENDING"],
          ["Affected Individuals", state.legalSubjectNotification === "REQUIRED" ? "DRAFT REQUIRED" : "ASSESSMENT PENDING"],
          ["Executive / DPO briefing", state.legalDecisionRecorded ? "READY" : "PENDING"],
          ["Compliance record", state.legalDecisionRecorded ? "PRESERVED" : "INCOMPLETE"]
        ].map(item => `<div class="ready-row ${["READY", "PRESERVED", "DRAFT REQUIRED"].includes(item[1]) ? "done" : ""}"><span>${["READY", "PRESERVED", "DRAFT REQUIRED"].includes(item[1]) ? "✓" : "?"}</span><span><strong>${item[0]}:</strong> ${item[1]}</span></div>`).join("");
      }
    }

    function renderApprovals() {
      if (!els.approvalQueue) return;
      if (state.role === "Incident Commander" && !state.approvals.length) {
        state.approvals.push({ id: "APR-0042", type: "Targeted Portal Isolation", status: "pending", elapsed: 0, needsInfo: false, requester: "Maya Chen — SOC Analyst", owner: "Incident Commander", evidenceAtRequest: Math.max(72, state.evidence), reason: "Active exploitation suspected; DB read anomaly observed; full exfiltration remains unconfirmed.", impact: "Portal degraded; ~120 customers may see slower responses; estimated downtime 8-12 min." });
      }
      els.approvalQueue.innerHTML = state.approvals.length ? state.approvals.map((item, index) => `<div class="workspace-card">
        <b>${item.id || `APR-${String(index + 42).padStart(4, "0")}`} | ${item.type}</b>
        <span class="small">Owner: ${item.owner || "Incident Commander"} | Requested by: ${item.requester || (state.user ? state.user.name : state.role)}</span>
        <span class="small">Evidence: ${item.evidenceAtRequest ?? state.evidence}% | Status: ${item.status === "pending" ? `PENDING ${String(Math.floor((item.elapsed || 0) / 60)).padStart(2, "0")}:${String((item.elapsed || 0) % 60).padStart(2, "0")}` : item.status.toUpperCase()}</span>
        <span class="small">Reason: ${item.reason || "High-impact action requested during active incident."}</span>
        <span class="small">Operational impact: ${item.impact || "Security benefit must be balanced against service availability."}</span>
        <span class="small ${item.evidenceAttached ? "" : "warning-text"}">${item.needsInfo ? "More evidence required: attach WAF/HTTP/DB artifacts before approval." : item.evidenceAttached ? "Evidence attached: yes" : "No validated evidence attached"}</span>
        <div class="actions">
          <button class="btn primary" data-review-approval="${index}" type="button">Review decision</button>
          <button class="btn" data-attach-evidence="${index}" type="button">Attach evidence</button>
          <button class="btn" data-more-info="${index}" type="button">More information required</button>
          <button class="btn" data-approve="${index}" type="button">Approve</button>
          <button class="btn" data-reject="${index}" type="button">Reject</button>
        </div>
      </div>`).join("") : `<div class="ready-row"><span>?</span><span>No pending approvals.</span></div>`;
      els.approvalQueue.querySelectorAll("[data-review-approval]").forEach(button => button.addEventListener("click", () => {
        const item = state.approvals[Number(button.dataset.reviewApproval)];
        openDrawer("APPROVE CONTAINMENT", `<div class="report-section"><strong>Request</strong><span>${item.id} | ${item.type}</span></div>
          <div class="report-section"><strong>Security benefit</strong><span>HIGH</span></div>
          <div class="report-section"><strong>Business disruption</strong><span>MEDIUM</span></div>
          <div class="report-section"><strong>Evidence confidence</strong><span>${item.evidenceAtRequest || state.evidence}%</span></div>
          <div class="report-section"><strong>Rollback available</strong><span>YES</span></div>
          <div class="login-field"><label for="commanderDecisionNote">Commander note</label><input id="commanderDecisionNote" placeholder="Reason for decision"></div>
          <div class="actions"><button class="btn primary" id="confirmApproveDecision" type="button">Approve</button><button class="btn" id="confirmMoreEvidence" type="button">Request more evidence</button><button class="btn ghost" id="confirmRejectDecision" type="button">Reject</button></div>`);
        $("confirmApproveDecision").addEventListener("click", () => {
          item.status = "approved";
          item.note = $("commanderDecisionNote").value || "Approved targeted containment based on current confidence.";
          applyCommanderDecision("targeted");
          logAction(`Approved ${item.id}: ${item.note}`, "Incident Commander");
          els.eventDrawer.classList.remove("open");
          renderApprovals();
        });
        $("confirmMoreEvidence").addEventListener("click", () => {
          item.status = "more information required";
          item.needsInfo = true;
          item.note = $("commanderDecisionNote").value || "Need stronger DB/egress evidence before high-impact action.";
          applyCommanderDecision("more");
          logAction(`Requested more evidence for ${item.id}: ${item.note}`, "Incident Commander");
          els.eventDrawer.classList.remove("open");
          renderApprovals();
        });
        $("confirmRejectDecision").addEventListener("click", () => {
          item.status = "rejected";
          item.note = $("commanderDecisionNote").value || "Rejected due to insufficient confidence or business impact.";
          logAction(`Rejected ${item.id}: ${item.note}`, "Incident Commander");
          els.eventDrawer.classList.remove("open");
          renderApprovals();
        });
      }));
      els.approvalQueue.querySelectorAll("[data-attach-evidence]").forEach(button => button.addEventListener("click", () => {
        const item = state.approvals[Number(button.dataset.attachEvidence)];
        item.evidenceAttached = true;
        item.needsInfo = false;
        logAction(`Evidence attached to approval: ${item.type}`);
        toast("Evidence attached", "Commander confidence improved.");
        renderApprovals();
      }));
      els.approvalQueue.querySelectorAll("[data-more-info]").forEach(button => button.addEventListener("click", () => {
        const item = state.approvals[Number(button.dataset.moreInfo)];
        item.needsInfo = true;
        item.status = "more information required";
        logAction(`Commander requested more information for ${item.type}`);
        toast("More info required", "Attach WAF/HTTP/DB evidence to improve handoff.", "bad");
        renderApprovals();
      }));
      els.approvalQueue.querySelectorAll("[data-approve]").forEach(button => button.addEventListener("click", () => {
        const item = state.approvals[Number(button.dataset.approve)];
        if (state.role === "Incident Commander" && !item.evidenceAttached) {
          item.needsInfo = true;
          item.status = "more information required";
          logAction(`Approval blocked pending validated evidence for ${item.type}`, "Incident Commander");
          toast("Approval blocked", "No validated evidence is attached yet.", "bad");
          renderApprovals();
          renderCommanderWarRoom();
          renderReportBuilder();
          return;
        }
        item.status = "approved";
        if (item.type.includes("PATCH-204")) {
          state.patchDeployed = true;
          if (state.incidentClock.recoveredAt === null) state.incidentClock.recoveredAt = state.elapsedSeconds;
          updateHandoff("commander", "PATCH-204 approved; waiting for stable production monitoring window.");
          updateHandoff("legal", "Remediation deployed; legal can include recovery status in disposition.");
          state.risk = clamp(state.risk - 14, 0, 100);
          state.serviceHealth = clamp(state.serviceHealth - 3, 0, 100);
          logAction("PATCH-204 deployment approved by Incident Commander", "Incident Commander");
        }
        state.risk = clamp(state.risk - 10, 0, 100);
        state.loss += item.type.includes("isolation") ? 12000 : 0;
        state.containmentTime = state.elapsedSeconds;
        logAction(`Approval granted: ${item.type}`);
        renderApprovals();
        renderMetrics();
        renderCommanderWarRoom();
        renderReportBuilder();
      }));
      els.approvalQueue.querySelectorAll("[data-reject]").forEach(button => button.addEventListener("click", () => {
        state.approvals[Number(button.dataset.reject)].status = "rejected";
        logAction(`Approval rejected: ${state.approvals[Number(button.dataset.reject)].type}`);
        toast("Request rejected", "Containment decision confidence reduced.", "bad");
        renderApprovals();
      }));
    }

    function closeDrawer() {
      if (!els.eventDrawer) return;
      els.eventDrawer.classList.remove("open");
      els.eventDrawer.setAttribute("aria-hidden", "true");
    }

    function openDrawer(title, body) {
      els.eventDrawer.innerHTML = `<div class="drawer-card simulation-card" role="document"><div class="drawer-head"><h2>${title}</h2><button class="btn ghost" id="closeDrawer" type="button">Close</button></div>${body}</div>`;
      els.eventDrawer.setAttribute("role", "dialog");
      els.eventDrawer.setAttribute("aria-modal", "true");
      els.eventDrawer.setAttribute("aria-hidden", "false");
      els.eventDrawer.classList.add("open");
      $("closeDrawer").addEventListener("click", closeDrawer);
    }

    function showContextMenu(x, y, evidenceId) {
      state.contextEvidenceId = evidenceId;
      els.contextMenu.style.display = "block";
      els.contextMenu.style.left = `${x}px`;
      els.contextMenu.style.top = `${y}px`;
    }

    function collectEvidence(id) {
      const row = evidenceGameRows.find(item => item.id === id);
      if (!row || state.collectedEvidence[id]) return;
      state.collectedEvidence[id] = true;
      const evidenceGain = row.id === "E-003" ? 16 : row.id === "E-005" ? 18 : row.id === "E-008" ? 22 : row.suspicious ? 10 : 3;
      if (row.suspicious) {
        state.evidence = clamp(state.evidence + evidenceGain, 0, 100);
        state.attackerHold = Math.max(state.attackerHold, 30);
        state.score += row.confidence === "High" ? 10 : 7;
        toast("Evidence preserved", `${row.id} added to case. Evidence quality +${evidenceGain}%`);
        logAction(`Collected evidence ${row.id}: ${row.source}`);
        if (id === "E-003") updateHandoff("commander", "HTTP exploit response attached; incident confidence improving.");
        if (id === "E-004") updateHandoff("commander", "WAF SQLI_GENERIC_17 correlated with customer endpoint.");
        if (id === "E-005") {
          updateHandoff("commander", "DB audit confirms 247 records potentially accessed.");
          updateHandoff("appsec", "Confirmed SQL injection evidence available for /customers?id=.");
          updateHandoff("legal", "DB access evidence available; personal-data assessment may be needed.");
        }
        if (id === "E-008") updateHandoff("legal", "Customer-impact signal added; external exfiltration still not established.");
        if (id === "E-005" && (state.collectedEvidence["E-007"] || state.collectedEvidence["E-008"])) state.recordsExposed = 247;
        if ((id === "E-007" || id === "E-008") && state.collectedEvidence["E-005"]) state.recordsExposed = 247;
        if (["E-003", "E-004"].includes(id)) state.objectiveStep = Math.max(state.objectiveStep, 1);
        if (["E-005", "E-006"].includes(id)) state.objectiveStep = Math.max(state.objectiveStep, 2);
      } else {
        state.evidence = clamp(state.evidence - 2, 0, 100);
        state.score -= 3;
        logAction(`Collected low-value evidence ${row.id}`);
        toast("Low-value evidence", "Context retained, but evidence quality -2%.", "bad");
      }
      renderEvidenceGame();
      renderMetrics();
      renderReportBuilder();
      renderObjective();
    }

    function aiResponse(type = "next") {
      const phase = current();
      const exposure = clamp(38 + state.risk * .5 - state.evidence * .25, 0, 100);
      const hasHttp = state.collectedEvidence["E-003"] || state.evidence >= 25;
      const hasDb = state.collectedEvidence["E-005"] || state.evidence >= 45;
      const hasCustomerImpact = state.collectedEvidence["E-008"] || state.recordsExposed !== null;
      const aiConfidence = clamp(41 + (hasHttp ? 18 : 0) + (hasDb ? 23 : 0) + (hasCustomerImpact ? 8 : 0) + Math.floor(state.evidence / 8), 0, 92);
      const hypothesis = hasHttp && hasDb ? "Confirmed exploitation; data access under scope" : "Possible SQL Injection";
      const reasoning = hasHttp && hasDb ?
        "WAF/HTTP payload is correlated with DB row-scan behavior from the web application role." :
        "WAF signature exists, but exploitation is not confirmed without HTTP response and DB evidence.";
      if (state.role === "Incident Commander") {
        if (type === "why") {
          return `AI COMMAND ADVISOR\n\nCurrent recommendation: Targeted containment\nConfidence: ${Math.round(commanderConfidence())}%\n\nWHY\n- Exploitation probability is increasing.\n- Customer-facing portal is affected.\n- Service remains healthy enough for targeted action.\n- Full isolation may be premature while exfiltration is unconfirmed.\n\nUNKNOWN\nActual data exfiltration remains unconfirmed.`;
        }
        if (type === "missing") {
          return `CONTAINMENT OPTIONS\n\nTargeted containment\nSecurity benefit: HIGH\nExpected downtime: LOW-MEDIUM\nCustomer disruption: limited\n\nFull portal isolation\nSecurity confidence: HIGHEST\nBusiness disruption: HIGH\nCustomer impact: significant\n\nWait for evidence\nEvidence improves, but attacker momentum may increase.`;
        }
        if (type === "challenge") {
          return `WHAT IF WE WAIT 5 MIN?\n\nExpected outcome:\n- Evidence confidence may improve by 8-15% if DB/support teams respond.\n- Attacker progress may increase by 10-18%.\n- Records accessed may remain scoped at 247 or rise if new DB evidence appears.\n\nDecision advice: wait only if SOC is actively preserving DB evidence and customer-impact telemetry.`;
        }
        return `AI COMMAND ADVISOR\n\nCurrent recommendation: Targeted containment\nConfidence: ${Math.round(commanderConfidence())}%\n\nBusiness trade-off:\n- Targeted containment: low expected downtime, good risk reduction.\n- Full isolation: strongest security, high customer disruption.\n- Waiting: better evidence, higher attacker momentum.\n\nCommander decision needed: approve targeted containment or request one more evidence update.`;
      }
      if (state.role === "AppSec Engineer") {
        const appsecConfidence = clamp(45 + (state.appsecExploitReproduced ? 18 : 0) + (state.appsecTraceInspected ? 14 : 0) + (state.appsecRootCauseConfirmed ? 16 : 0) + (state.patchTested ? 12 : 0), 35, 94);
        if (type === "why") {
          return `AI APPSEC ASSISTANT\n\nSuspected root cause: dynamic SQL query construction\nConfidence: ${appsecConfidence}%\nRelevant code: customerController.js:43\n\nWhy this matters:\n- req.query.id is user-controlled input.\n- The value is concatenated into a SQL string.\n- db.query() executes the constructed SQL.\n\nRecommended remediation: parameterized query with bound id parameter.`;
        }
        if (type === "missing" || type === "tests") {
          return `SECURITY TEST PLAN\n\nRequired tests before deployment:\n1. Normal customer lookup returns the same authorized record.\n2. Invalid ID is rejected safely.\n3. SQL injection payload is blocked by parameterization.\n4. Authorization behavior is preserved for customer records.\n\nCurrent status: ${state.patchTested ? "3/3 security regression tests passed." : "tests not complete."}`;
        }
        if (type === "challenge") {
          return `CHALLENGE PATCH\n\nThe parameterized query prevents SQL injection, but verify two things before deployment:\n- Does the endpoint still enforce customer authorization, or can one user request another user's ID?\n- Did the patch preserve normal lookup behavior and error handling?\n\nDo not treat a WAF rule as remediation. It is containment, not root-cause fix.`;
        }
        return `AI APPSEC ASSISTANT\n\nFinding: suspected SQL injection in /customers?id=\nConfidence: ${appsecConfidence}%\n\nRecommended workflow:\n- Accept SOC handoff.\n- Reproduce exploit safely in lab.\n- Trace req.query.id to db.query().\n- Confirm dynamic SQL root cause.\n- Apply parameterized query patch.\n- Run security regression tests.\n- Request Incident Commander deployment approval.`;
      }
      if (state.role === "Legal/Compliance") {
        const selectedClasses = Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]);
        if (type === "why") {
          return `AI LEGAL / COMPLIANCE ASSISTANT\n\nNotification threshold explanation:\nA personal-data breach assessment depends on confirmed facts, affected data categories, likely consequences, and risk to individuals.\n\nImportant nuance:\nA regulatory clock starts when the controller is aware enough to assess a personal-data breach, not simply when the attack began.\n\nCurrent posture: ${state.legalBreachStatus === "CONFIRMED" ? "breach confirmed" : "under assessment"}.`;
        }
        if (type === "missing") {
          return `MISSING LEGAL EVIDENCE\n\nNeeded before final decision:\n- Categories of personal data involved.\n- Approximate number of affected data subjects.\n- Whether data left the environment.\n- Containment/remediation summary.\n- Written rationale for notification decision.\n\nCurrent data classes: ${selectedClasses.length ? selectedClasses.join(", ") : "none classified yet"}.`;
        }
        if (type === "challenge") {
          return `CHALLENGE LEGAL CONCLUSION\n\nDo not overstate facts:\n- Exfiltration is not automatically confirmed by SQLi.\n- Not every security incident is automatically reportable.\n- Customer communications must separate confirmed, likely, and unknown facts.\n\nBest next step: preserve rationale and approve only evidence-backed language.`;
        }
        return `AI LEGAL / COMPLIANCE ASSISTANT\n\nCurrent assessment: potential personal-data breach involving customer records.\n\nKnown facts:\n- Customer portal affected.\n- SQL injection suspected.\n- Customer records may have been accessed.\n- Exfiltration is not yet fully confirmed.\n\nRecommended next action:\nClassify personal data, assess risk to individuals, document notification decision, and review external communications.`;
      }
      if (type === "missing") {
        return `AI MISSING EVIDENCE\n\nTo confirm exploitation, collect:\n1. HTTP response associated with WAF-1192\n2. Database audit activity from web_portal_ro\n3. Related requests from 198.51.100.24\n4. Outbound transfer or customer-impact signal\n\nI would not confirm data exfiltration yet. Current evidence quality: ${state.evidence}%.`;
      }
      if (type === "why") {
        return `AI EXPLANATION\n\nHypothesis: ${hypothesis}\nConfidence: ${aiConfidence}%\n\nReasoning:\n${reasoning}\n\nCurrent signals:\n- WAF SQLI_GENERIC_17: ${state.collectedEvidence["E-004"] ? "collected" : "observed"}\n- HTTP exploit response: ${hasHttp ? "available" : "missing"}\n- DB read anomaly: ${hasDb ? "available" : "missing"}\n- Exfiltration proof: ${hasExfil ? "possible/observed" : "not confirmed"}\n\nLimitation: do not declare data exfiltration without preserved DB, HTTP, and egress evidence.`;
      }
      if (type === "challenge") {
        return `AI CHALLENGE MODE\n\nAlternative explanations:\n- benign scanner or QA traffic\n- WAF false positive\n- DB anomaly caused by batch job\n\nTo reject the SQLi hypothesis, prove normal authorized source, normal query path, and no unusual response size.`;
      }
      if (type === "exec") {
        return `AI EXECUTIVE BRIEF\n\nCurrent phase: ${phase.title}\nRisk: ${state.risk}% | Evidence: ${state.evidence}% | Estimated loss: ${money(state.loss)}\n\nBusiness meaning: a CTF-style SQL injection has become a possible customer-data incident. The priority is to reduce active exploitation while proving scope with preserved evidence.\n\nBoard-level message: containment is ${state.risk < 30 ? "on track" : "still in progress"}; legal confidence is ${state.evidence > 55 ? "improving" : "not yet strong enough"}.`;
      }
      if (type === "legal") {
        return `AI LEGAL CHECKLIST\n\nLegal needs:\n1. Confirmed timeline and first suspicious request.\n2. Data classes possibly accessed.\n3. Whether external exfiltration is established.\n4. Actions already taken to contain the exploit.\n5. Next update time and report owner.\n\nCurrent confidence: ${state.evidence > 60 ? "strong" : state.evidence > 30 ? "moderate" : "weak"}.\nPotential exposure score: ${Math.round(exposure)}%.`;
      }
      return `AI INCIDENT ASSISTANT\n\nHypothesis: ${hypothesis}\nConfidence: ${aiConfidence}%\n\nReasoning:\n${reasoning}\n\nMissing evidence:\n${hasHttp ? "- HTTP exploit response: collected" : "- HTTP response associated with WAF-1192"}\n${hasDb ? "- DB query confirmation: collected" : "- DB query confirmation from web_portal_ro"}\n${hasCustomerImpact ? "- Customer-impact signal: observed" : "- Customer-impact proof"}\n\nSuggested next query: source.ip:198.51.100.24 AND path:/customers\n\nI will not confirm external exfiltration until evidence supports it.`;
    }

    function typeAi(text) {
      els.aiAnswer.textContent = "";
      let i = 0;
      const step = () => {
        els.aiAnswer.textContent = text.slice(0, i);
        i += 3;
        if (i <= text.length + 3) window.setTimeout(step, 8);
      };
      step();
    }

    function renderAI(type = "next") {
      typeAi(aiResponse(type));
      const recs = state.role === "Incident Commander" ? [
        ["targeted", "Review decision", "Approve targeted containment with limited customer disruption."],
        ["more", "Review decision", "Request one more DB/egress evidence update before authorization."],
        ["isolate", "Review decision", "Full portal isolation: highest security, highest customer impact."]
      ] : state.role === "AppSec Engineer" ? [
        ["appsec-why", "Explain root cause", "Trace user input from req.query.id to SQL execution."],
        ["appsec-patch", "Suggest patch", "Use a parameterized query instead of dynamic SQL concatenation."],
        ["appsec-test", "Generate security test", "Validate normal lookup, invalid input, and SQLi payload behavior."]
      ] : state.role === "Legal/Compliance" ? [
        ["legal-why", "Explain notification threshold", "Clarify when notification may be required."],
        ["legal-missing", "What evidence is missing?", "List facts needed before final legal decision."],
        ["legal-challenge", "Challenge legal conclusion", "Stress-test wording and assumptions."]
      ] : state.evidence < 25 ? [
        ["evidence", "Review action", "Preserve HTTP/WAF/DB evidence before destructive changes."],
        ["contain", "Low-confidence suggestion", "Do not block broadly yet; validate HTTP response and DB activity first."],
        ["hardening", "Review action", "Prepare patch hypothesis, but avoid declaring root cause without code inspection."]
      ] : [
        ["contain", "Review action", "Block SQLI_GENERIC_17 after validating evidence and operational impact."],
        ["evidence", "Review action", "Preserve HTTP/WAF/DB evidence before destructive changes."],
        ["hardening", "Review action", "Prepare patch and regression tests; do not deploy blindly."]
      ];
      els.recommendations.innerHTML = recs.map(rec => `<div class="rec-card ${state.appliedRecs[rec[0]] ? "applied" : ""}">
        <strong>${rec[1]}</strong>
        <p>${rec[2]}</p>
        <button type="button" data-rec="${rec[0]}" ${state.appliedRecs[rec[0]] ? "disabled" : ""}>${state.appliedRecs[rec[0]] ? "Executed" : "Review action"}</button>
      </div>`).join("");
      els.recommendations.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => {
          if (state.role === "Incident Commander") return applyCommanderDecision(button.dataset.rec);
          if (state.role === "AppSec Engineer") {
            if (button.dataset.rec === "appsec-why") return renderAI("why");
            if (button.dataset.rec === "appsec-patch") {
              state.appsecSelectedPatch = "parameterized";
              showPage("appsec");
              renderAppSec();
              return toast("Patch suggested", "Parameterized query selected in Patch Builder.");
            }
            return renderAI("tests");
          }
          if (state.role === "Legal/Compliance") {
            if (button.dataset.rec === "legal-why") return renderAI("why");
            if (button.dataset.rec === "legal-missing") return renderAI("missing");
            return renderAI("challenge");
          }
          return reviewAction(button.dataset.rec);
        });
      });
      const stream = [
        ["now", `Correlated ${current().feed.length} live signals with phase ${flowNames[state.phase]}.`],
        ["+04s", state.evidence < 40 ? "Evidence confidence remains low; preserve logs before patching." : "Evidence chain is usable for legal and executive reporting."],
        ["+09s", state.risk > 55 ? "Attacker momentum is high; containment should be prioritized." : "Risk is manageable if monitoring continues."],
        ["+14s", `Recommended briefing mode: ${state.phase < 2 ? "technical triage" : "executive impact"}.`]
      ];
      els.aiStream.innerHTML = stream.map(line => `<div class="ai-stream-line"><b>${line[0]}</b><span>${line[1]}</span></div>`).join("");
      const confidence = [
        ["Scope", clamp(state.evidence * .75 + state.phase * 10, 0, 100)],
        ["Containment", clamp(100 - state.risk + state.score * .2, 0, 100)],
        ["Legal", clamp(state.evidence * .6 + (state.phase > 1 ? 22 : 0), 0, 100)]
      ];
      els.confidenceRows.innerHTML = confidence.map(row => `<div class="confidence-row">
        <span>${row[0]}</span>
        <div class="confidence-track"><span style="width:${row[1]}%"></span></div>
        <span>${Math.round(row[1])}%</span>
      </div>`).join("");
      els.tickerTrack.innerHTML = [
        `<span><b>AI</b> correlating ${current().feed.length} live events</span>`,
        `<span><b>Risk</b> ${state.risk}%</span>`,
        `<span><b>Evidence</b> ${state.evidence}%</span>`,
        `<span><b>Loss</b> ${money(state.loss)}</span>`,
        `<span><b>Phase</b> ${flowNames[state.phase]}</span>`
      ].join("");
    }

    function renderLivePulse() {
      if (state.paused) {
        if (els.liveResponder) els.liveResponder.textContent = "simulation paused for presenter";
        return;
      }
      state.liveTick += 1;
      const messages = [
        `AI re-scored exploit likelihood at ${clamp(state.risk + (state.liveTick % 3) - 1, 0, 100)}%.`,
        `New correlation pass checked WAF, HTTP, DB audit, IAM, and support signals.`,
        state.evidence < 50 ? "AI warning: evidence is still not strong enough for final scope." : "AI note: evidence is strong enough for a preliminary executive summary.",
        state.risk > 55 ? "AI escalation: containment should be treated as time-critical." : "AI update: containment path is stable if monitoring continues."
      ];
      const now = current().time;
      const lines = [
        ["live", messages[state.liveTick % messages.length]],
        ["phase", `${flowNames[state.phase]} active. ${current().feed[state.activeEvent]?.title || "SOC signal"} selected.`],
        ["risk", `Risk ${state.risk}% | Evidence ${state.evidence}% | Loss ${money(state.loss)}`]
      ];
      els.aiStream.innerHTML = lines.map(line => `<div class="ai-stream-line"><b>${line[0]}</b><span>${now} - ${line[1]}</span></div>`).join("");
      els.tickerTrack.innerHTML = [
        `<span><b>LIVE</b> ${messages[state.liveTick % messages.length]}</span>`,
        `<span><b>Risk</b> ${state.risk}%</span>`,
        `<span><b>Evidence</b> ${state.evidence}%</span>`,
        `<span><b>Selected event</b> ${current().feed[state.activeEvent]?.title || "none"}</span>`
      ].join("");
      const packetMessages = [
        state.collectedEvidence["E-003"] ? "SQLi payload confirmed in HTTP response" : "Suspicious request detected",
        state.appliedRecs.contain || state.commandDecision === "targeted containment" ? "payload blocked by WAF rule SQLI-CUSTOMERS" : "customer endpoint still under review",
        state.patchDeployed ? "normal customer traffic healthy" : "normal traffic baseline pending",
        state.collectedEvidence["E-004"] ? "WAF signature correlated" : "WAF signal unvalidated"
      ];
      const siemMessages = [
        state.collectedEvidence["E-004"] && state.collectedEvidence["E-005"] ? "WAF-1192 linked with DB-8841" : "Correlation pending",
        state.terminalLines.some(line => line.includes("12 events found")) ? "same source touched /customers repeatedly" : "related traffic search pending",
        socScoped() ? "incident timeline confidence high" : "incident timeline confidence low",
        Object.keys(state.collectedEvidence).length ? "new evidence attached to INC-2026-0812" : "no preserved evidence yet"
      ];
      const dbMessages = [
        state.collectedEvidence["E-005"] ? "247 records accessed by web_portal_ro" : "Review pending",
        state.terminalLines.some(line => line.includes("credential")) ? "web_portal_ro credential rotated" : "credential rotation not started",
        state.patchDeployed ? "query volume returning to baseline" : "query baseline not validated",
        state.terminalLines.some(line => line.includes("snapshot")) ? "audit snapshot preserved" : "audit snapshot pending"
      ];
      const responderMessages = [
        state.inboxStatuses.waf ? "SOC-L2 reviewing event detail" : "No response action yet",
        state.appsecHandoffAccepted ? "AppSec reproducing and patching" : "AppSec not assigned",
        state.legalHandoffAccepted ? "Legal assessing confirmed facts" : "Legal not handed off",
        state.commandDecision ? "Business owner tracking decision impact" : "Business owner waiting for command decision"
      ];
      if (state.role === "Legal/Compliance") {
        els.livePacket.textContent = "potential personal-data breach";
        els.liveSiem.textContent = state.legalExposureSaved ? "data exposure under legal assessment" : "data exposure unconfirmed";
        els.liveDb.textContent = state.legalClockStartedAt === null ? "regulatory clock not started" : "regulatory clock active";
        els.liveResponder.textContent = Object.keys(state.legalComms).length ? "communications under legal review" : "communications pending legal approval";
      } else {
        els.livePacket.textContent = packetMessages[state.liveTick % packetMessages.length];
        els.liveSiem.textContent = siemMessages[(state.liveTick + state.phase) % siemMessages.length];
        els.liveDb.textContent = dbMessages[(state.liveTick + state.selectedKillStep) % dbMessages.length];
        els.liveResponder.textContent = responderMessages[(state.liveTick + state.activeEvent) % responderMessages.length];
      }
      state.elapsedSeconds += Math.max(1, Math.round(7 * state.demoSpeed));
      maybeIncidentInjects();
      state.approvals.forEach(item => {
        if (item.status === "pending") item.elapsed = (item.elapsed || 0) + Math.max(1, Math.round(7 * state.demoSpeed));
      });
      if (state.role === "Incident Commander" && !state.commandDecision && !state.commanderSlaBreached && state.elapsedSeconds >= 180) {
        state.commanderSlaBreached = true;
        state.risk = clamp(state.risk + 6, 0, 100);
        state.score -= 6;
        state.loss += 18000;
        logAction("Decision SLA breached before containment decision", "Executive Oversight");
        toast("SLA breached", "Leadership confidence dropped and business risk increased.", "bad");
      }
      const contained = state.appliedRecs.contain || state.checks.owner || state.risk < 25;
      if (state.attackerHold > 0) state.attackerHold -= Math.max(1, Math.round(7 * state.demoSpeed));
      const stageGate = state.objectiveStep === 0 ? 34 : state.objectiveStep === 1 ? 58 : state.objectiveStep === 2 ? 82 : 100;
      if (!contained && state.attackerHold <= 0 && state.liveTick % Math.max(3, Math.round(7 / state.demoSpeed)) === 0 && state.attackerProgress < stageGate) {
        state.attackerProgress = clamp(state.attackerProgress + (state.evidence > 55 ? 2 : 5), 0, 100);
        state.risk = clamp(state.risk + (state.attackerProgress > 45 ? 2 : 1), 0, 100);
        if (state.attackerProgress > 76) state.loss += 9500;
        logAction(`Attacker momentum increased during ${workflowAttackStage()}`, "Telemetry");
      }
      renderMetrics();
      renderApprovals();
      const sceneBody = els.phaseRealScene?.querySelector(".scene-body");
      if (sceneBody && state.liveTick % 2 === 0) {
        const line = document.createElement("div");
        line.className = "scene-line live-insert";
        line.innerHTML = `<span class="ts">live</span><span>${messages[state.liveTick % messages.length]}</span>`;
        sceneBody.prepend(line);
        Array.from(sceneBody.querySelectorAll(".live-insert")).slice(4).forEach(item => item.remove());
      }
    }

    function reviewAction(id) {
      const details = {
        contain: ["Block SQLI_GENERIC_17", "Stops known payload pattern", "May not stop payload variations", "None", "No"],
        evidence: ["Preserve HTTP/WAF/DB evidence", "Improves scope confidence", "Takes analyst time while attacker may continue", "Positive", "No"],
        hardening: ["Prepare patch and regression tests", "Reduces recurrence", "Deploying too early can affect forensic state", "Neutral", "AppSec approval"]
      }[id] || ["Review action", "Unknown", "Unknown", "Unknown", "Unknown"];
      openDrawer("Review AI-proposed action", `<div class="report-section"><strong>Proposed action</strong><span>${details[0]}</span></div>
        <div class="report-section"><strong>Expected benefit</strong><span>${details[1]}</span></div>
        <div class="report-section"><strong>Risk</strong><span>${details[2]}</span></div>
        <div class="report-section"><strong>Evidence impact</strong><span>${details[3]}</span></div>
        <div class="report-section"><strong>Requires approval</strong><span>${details[4]}</span></div>
        <div class="actions"><button class="btn primary" id="executeReviewedAction" type="button">Execute</button><button class="btn ghost" id="cancelReviewedAction" type="button">Cancel</button></div>`);
      $("executeReviewedAction").addEventListener("click", () => {
        applyRecommendation(id);
        els.eventDrawer.classList.remove("open");
      });
      $("cancelReviewedAction").addEventListener("click", () => els.eventDrawer.classList.remove("open"));
    }

    function applyRecommendation(id) {
      if (state.appliedRecs[id]) return;
      state.appliedRecs[id] = true;
      if (id === "contain") {
        state.risk = clamp(state.risk - 7, 0, 100);
        state.attackerHold = 45;
        state.containmentTime = state.elapsedSeconds;
        state.score += 6;
      }
      if (id === "evidence") {
        state.evidence = clamp(state.evidence + 10, 0, 100);
        state.attackerHold = 30;
        state.score += 5;
      }
      if (id === "hardening") {
        state.risk = clamp(state.risk - 4, 0, 100);
        state.evidence = clamp(state.evidence + 3, 0, 100);
        state.score += 4;
      }
      renderMetrics();
      renderImpactMonitor();
      renderAI("next");
      renderObjective();
      renderReportBuilder();
      logAction(`Executed AI-reviewed action: ${id}`);
      toast("Action executed", `${id} action applied with human approval.`);
    }

    function renderPhases() {
      if (els.phasePanelTitle) {
        els.phasePanelTitle.textContent = state.role === "AppSec Engineer" ? "Remediation Workflow" : state.role === "Legal/Compliance" ? "Legal / Compliance Workflow" : "Incident Phases";
      }
      if (state.role === "Incident Commander") {
        const commanderPhases = [
          ["Accept incident command", state.commanderAccepted],
          ["Assess business impact", state.evidence >= 20 || state.approvals.length > 0],
          ["Decide containment", state.commandDecision || state.containmentTime !== null],
          ["Coordinate stakeholders", Object.keys(state.commandComms).length >= 2],
          ["Authorize recovery", state.patchDeployed || state.phase >= 3],
          ["Executive closure", state.reportReadiness >= 80]
        ];
        const activeIndex = commanderPhases.findIndex(item => !item[1]);
        els.phases.innerHTML = commanderPhases.map((item, index) => {
          const done = item[1];
          const current = index === (activeIndex === -1 ? commanderPhases.length - 1 : activeIndex);
          return `<div class="phase ${done ? "done" : current ? "current" : ""}">
            <span class="dot">${done ? "✓" : current ? "●" : "○"}</span>
            <div><strong>${item[0]}</strong><span>${done ? "completed" : current ? "active command step" : "locked"}</span></div>
          </div>`;
        }).join("");
        return;
      }
      if (state.role === "AppSec Engineer") {
        const appsecPhases = [
          ["Accept security handoff", state.appsecHandoffAccepted],
          ["Reproduce vulnerability", state.appsecExploitReproduced],
          ["Identify root cause", state.appsecRootCauseConfirmed],
          ["Build patch", state.appsecPatchApplied],
          ["Validate remediation", state.patchTested],
          ["Request deployment", state.appsecDeploymentRequested || state.patchDeployed],
          ["Verify fix", state.patchDeployed]
        ];
        const activeIndex = appsecPhases.findIndex(item => !item[1]);
        els.phases.innerHTML = appsecPhases.map((item, index) => {
          const done = item[1];
          const current = index === (activeIndex === -1 ? appsecPhases.length - 1 : activeIndex);
          return `<div class="phase ${done ? "done" : current ? "current" : ""}">
            <span class="dot">${done ? "✓" : current ? "●" : "○"}</span>
            <div><strong>${item[0]}</strong><span>${done ? "complete" : current ? "active remediation step" : "locked"}</span></div>
          </div>`;
        }).join("");
        return;
      }
      if (state.role === "Legal/Compliance") {
        const legalPhases = [
          ["Accept legal handoff", state.legalHandoffAccepted],
          ["Assess data exposure", state.legalExposureSaved],
          ["Classify affected data", Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]).length >= 3],
          ["Determine notification obligations", state.legalDecisionRecorded],
          ["Start regulatory clock", state.legalClockStartedAt !== null],
          ["Review communications", Object.keys(state.legalComms).length >= 2],
          ["Preserve compliance evidence", state.reportReadiness >= 70],
          ["Issue legal decision", state.reportReadiness >= 85]
        ];
        const activeIndex = legalPhases.findIndex(item => !item[1]);
        els.phases.innerHTML = legalPhases.map((item, index) => {
          const done = item[1];
          const current = index === (activeIndex === -1 ? legalPhases.length - 1 : activeIndex);
          return `<div class="phase ${done ? "done" : current ? "current" : ""}">
            <span class="dot">${done ? "✓" : current ? "●" : "○"}</span>
            <div><strong>${item[0]}</strong><span>${done ? "complete" : current ? "active compliance step" : "locked"}</span></div>
          </div>`;
        }).join("");
        return;
      }
      els.phases.innerHTML = phases.map((phase, index) => {
        const status = index < state.phase ? "done" : index === state.phase ? "current" : "";
        const icon = index < state.phase ? "✓" : index === state.phase ? "●" : "○";
        const detail = state.history[index]?.choice || (index === state.phase ? "Decision required before next phase" : "Awaiting prior decision");
        return `<div class="phase ${status}">
          <span class="dot">${icon}</span>
          <div><strong>${phase.title}</strong><span>${detail}</span></div>
        </div>`;
      }).join("");
    }

    function renderBriefing() {
      const briefing = phaseBriefings[state.phase];
      const cards = [
        ["Attacker activity", briefing.attacker],
        ["Defender mission", briefing.defender],
        ["Business pressure", briefing.business],
        ["Success signal", briefing.success]
      ];
      els.briefingGrid.innerHTML = cards.map(card => `<div class="brief-card">
        <b>${card[0]}</b>
        <p>${card[1]}</p>
      </div>`).join("");
      els.flowStrip.innerHTML = flowNames.map((name, index) => {
        const status = index < state.phase ? "done" : index === state.phase ? "active" : "";
        return `<div class="flow-step ${status}"><strong>${name}</strong><span>${index < state.phase ? "completed" : index === state.phase ? "active now" : "up next"}</span></div>`;
      }).join("");
    }

    function renderImpactMonitor() {
      const dataExposure = clamp(38 + state.risk * .5 - state.evidence * .25, 0, 100);
      const downtime = clamp(18 + state.loss / 9000 + state.phase * 8, 0, 100);
      const legalPressure = clamp(22 + dataExposure * .55 + state.phase * 6, 0, 100);
      const attackerMomentum = clamp(state.risk + (state.selected ? -8 : 10), 0, 100);
      const heatRows = [
        ["Data", dataExposure],
        ["Downtime", downtime],
        ["Legal", legalPressure],
        ["Attacker", attackerMomentum]
      ];
      els.impactHeat.innerHTML = heatRows.map(row => `<div class="heat-row">
        <span>${row[0]}</span>
        <div class="heat-track"><span style="width: ${row[1]}%"></span></div>
        <span>${Math.round(row[1])}%</span>
      </div>`).join("");
      const lights = [
        ["Portal", state.risk > 70 ? "bad" : state.risk > 35 ? "warn" : "", state.risk > 70 ? "degraded" : state.risk > 35 ? "at risk" : "stable"],
        ["Evidence", state.evidence < 25 ? "bad" : state.evidence < 55 ? "warn" : "", state.evidence < 25 ? "weak" : state.evidence < 55 ? "improving" : "strong"],
        ["Response", state.score < 0 ? "bad" : state.score < 20 ? "warn" : "", state.score < 0 ? "poor" : state.score < 20 ? "forming" : "coordinated"]
      ];
      els.statusLights.innerHTML = lights.map(item => `<div class="status-light ${item[1]}">
        <strong>${item[0]}</strong>
        <span>${item[2]}</span>
      </div>`).join("");
    }

    function renderEvidence() {
      const phase = current();
      if (state.role === "AppSec Engineer") {
        const appsecEvidence = {
          "Code": {
            explain: "Source-level evidence for the vulnerable endpoint and the remediation target.",
            log: state.appsecTraceInspected ? "controllers/customerController.js:43 concatenates req.query.id into SQL before db.query()." : "Code trace not inspected yet. Open AppSec Workspace and click Inspect code."
          },
          "App Trace": {
            explain: "Application request flow from HTTP parameter to database execution.",
            log: state.appsecTraceInspected ? "GET /customers?id=12' UNION SELECT ... -> req.query.id -> query string -> db.query(query)" : "Trace unavailable until code inspection runs."
          },
          "DB Query": {
            explain: "Generated query behavior observed during safe exploit reproduction.",
            log: state.appsecExploitReproduced ? "Baseline: 1 customer row. Injected: response delta +4.8 KB and web_portal_ro query anomaly detected." : "Run safe reproduction to compare baseline and injected behavior."
          },
          "Patch Evidence": {
            explain: "Patch diff and regression-test proof for remediation.",
            log: state.appsecPatchApplied ? `PATCH-204 replaces dynamic SQL with parameterized query. Regression: ${state.patchTested ? "3/3 passed." : "not run yet."}` : "No patch evidence yet. Confirm root cause and apply parameterized query."
          }
        };
        const names = Object.keys(appsecEvidence);
        if (!state.activeTab || !appsecEvidence[state.activeTab]) state.activeTab = names[0];
        els.tabs.innerHTML = names.map(name => `<button class="tab ${name === state.activeTab ? "active" : ""}" type="button" data-tab="${name}">${name}</button>`).join("");
        els.tabs.querySelectorAll("button").forEach(button => {
          button.addEventListener("click", () => {
            state.activeTab = button.dataset.tab;
            renderEvidence();
          });
        });
        els.evidenceExplain.textContent = appsecEvidence[state.activeTab].explain;
        els.evidenceLog.textContent = appsecEvidence[state.activeTab].log;
        return;
      }
      if (state.role === "Legal/Compliance") {
        const selectedClasses = Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]);
        const legalEvidence = {
          "Incident Facts": {
            explain: "Confirmed and likely facts Legal can rely on without doing raw SOC hunting.",
            log: "Incident: INC-2026-0812\nSystem: Customer Portal\nKnown: SQL injection suspected; customer records may have been accessed\nUnknown: final exfiltration proof and exact affected population"
          },
          "Personal Data": {
            explain: "Potentially affected personal data categories and evidence posture.",
            log: `Email: DB-8841 / Confirmed\nPassword hash: HTTP-8841 / Likely\nPhone: DB query / Possible\nPayment card: None / Not evidenced\nSelected classes: ${selectedClasses.length ? selectedClasses.join(", ") : "none"}`
          },
          "Exposure": {
            explain: "Exposure and risk-to-individuals assessment.",
            log: state.legalExposureSaved ? "Personal data access: Confirmed\nExternal exfiltration: Not established\nData subjects: 247 confirmed\nRisk to individuals: MODERATE" : "Exposure assessment not saved yet."
          },
          "Business Impact": {
            explain: "Business context that informs communication timing and stakeholder briefings.",
            log: `Service health: ${state.serviceHealth}%\nRisk: ${state.risk}%\nCustomer support signal: profile mix-up reports under review`
          },
          "Legal Record": {
            explain: "Decision record, rationale, notification posture, and compliance package.",
            log: state.legalDecisionRecorded ? `Breach: ${state.legalBreachStatus}\nAuthority notification: ${state.legalAuthorityNotification}\nData subject notification: ${state.legalSubjectNotification}\nRationale: ${state.legalRationale || "documented in assessment"}` : "Legal decision not recorded yet."
          }
        };
        const names = Object.keys(legalEvidence);
        if (!state.activeTab || !legalEvidence[state.activeTab]) state.activeTab = names[0];
        els.tabs.innerHTML = names.map(name => `<button class="tab ${name === state.activeTab ? "active" : ""}" type="button" data-tab="${name}">${name}</button>`).join("");
        els.tabs.querySelectorAll("button").forEach(button => button.addEventListener("click", () => {
          state.activeTab = button.dataset.tab;
          renderEvidence();
        }));
        els.evidenceExplain.textContent = legalEvidence[state.activeTab].explain;
        els.evidenceLog.textContent = legalEvidence[state.activeTab].log;
        return;
      }
      const names = Object.keys(phase.evidence);
      if (!state.activeTab || !phase.evidence[state.activeTab]) state.activeTab = names[0];
      els.tabs.innerHTML = names.map(name => `<button class="tab ${name === state.activeTab ? "active" : ""}" type="button" data-tab="${name}">${name}</button>`).join("");
      els.tabs.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => {
          state.activeTab = button.dataset.tab;
          renderEvidence();
        });
      });
      els.evidenceExplain.textContent = phase.evidence[state.activeTab].explain;
      els.evidenceLog.textContent = phase.evidence[state.activeTab].log;
    }

    function renderFeed() {
      els.feed.innerHTML = current().feed.map((item, index) => `<button class="feed-item ${index === state.activeEvent ? "active" : ""}" type="button" data-event="${index}">
        <span class="time">${item.time}</span>
        <div><strong>${item.title}</strong><span>${item.summary}</span></div>
      </button>`).join("");
      els.feed.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => {
          state.activeEvent = Number(button.dataset.event);
          renderFeed();
          renderEventDetail();
        });
      });
      renderEventDetail();
    }

    function renderEventDetail() {
      const event = current().feed[state.activeEvent] || current().feed[0];
      els.eventDetail.innerHTML = `
        <p>${event.detail}</p>
        <div class="detail-grid">
          <div class="detail-box"><span>Source</span><strong>${event.source}</strong></div>
          <div class="detail-box"><span>Severity</span><strong>${event.severity}</strong></div>
          <div class="detail-box"><span>Impact</span><strong>${event.impact}</strong></div>
          <div class="detail-box"><span>Response</span><strong>${event.response}</strong></div>
        </div>`;
    }

    function renderEvidenceTimeline() {
      if (!els.evidenceTimeline) return;
      const all = phases.flatMap((phase, phaseIndex) => phase.feed.map(event => ({
        ...event,
        phase: flowNames[phaseIndex]
      })));
      els.evidenceTimeline.innerHTML = all.map(event => `<button class="feed-item" type="button">
        <span class="time">${event.time}</span>
        <div><strong>${event.phase}: ${event.title}</strong><span>${event.detail}</span></div>
      </button>`).join("");
    }

    function renderRoles() {
      if (!els.roleGrid) return;
      const account = state.user || demoAccounts["maya.chen"];
      const visibleRoles = roles.filter(role => role[0] === state.role);
      els.roleGrid.innerHTML = visibleRoles.map(role => `<div class="role-card active">
        <b>${role[0]}</b><span>${role[1]}</span><span>${account.name} · ${account.shift} · ${account.clearance}</span>
      </div>`).join("");
      const role = roles.find(item => item[0] === state.role) || roles[0];
      const access = roleAccess[state.role];
      els.roleBrief.innerHTML = `
        <h3>${role[0]} briefing</h3>
        <div class="report-section"><strong>Your focus</strong><span>${role[1]}</span></div>
        <div class="report-section"><strong>Visible modules</strong><span>${access.modules.join(", ")}</span></div>
        <div class="report-section"><strong>Access console</strong><span>${access.console.join(" | ")}</span></div>
        <div class="report-section"><strong>Current mission</strong><span>${state.role === "Legal/Compliance" ? "Ask for evidence-backed scope before declaring breach." : state.role === "AppSec Engineer" ? "Verify root cause and deploy the safe patch." : state.role === "Incident Commander" ? "Coordinate SOC, AppSec, legal, support, and business owners." : "Triage alerts and preserve evidence before changes."}</span></div>
        <div class="report-section"><strong>Live context</strong><span>Risk ${state.risk}%, evidence ${state.evidence}%, loss ${money(state.loss)}.</span></div>`;
    }

    function animateCountUps(root = document) {
      const items = root.querySelectorAll(".count-up");
      items.forEach(item => {
        const target = Number(item.dataset.countTo || 0);
        const suffix = item.dataset.countSuffix || "";
        const duration = 1200;
        const startedAt = performance.now();
        function tick(now) {
          const progress = clamp((now - startedAt) / duration, 0, 1);
          const eased = 1 - Math.pow(1 - progress, 3);
          item.textContent = `${Math.round(target * eased)}${suffix}`;
          if (progress < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
      });
    }

    function renderLogin() {
      if (!els.loginPanel) return;
      function enterRole(account) {
        state.user = account;
        state.role = account.role;
        state.loggedIn = true;
        state.selectedLoginRole = null;
        saveSession(account);
        state.terminalLines.push(`Authentication successful: ${account.name} (${account.role})`);
        renderLogin();
        renderRoles();
        renderTerminal();
        showPage(roleAccess[state.role].home);
        logAction(`Role login and handoff received: ${account.role}`, account.name);
        openRoleBriefing(account);
        renderAI("next");
        return;
        if (state.role === "Incident Commander") {
          const commandActionHtml = state.commanderAccepted
            ? `<div class="ready-row done"><span>✓</span><span>Command accepted. Continue with containment and stakeholder coordination.</span></div><div class="actions"><button class="btn" type="button" id="requestEvidenceFromHandoff">Request more evidence</button></div>`
            : `<div class="actions"><button class="btn primary" type="button" id="acceptCommandFromHandoff">Accept command</button><button class="btn" type="button" id="requestEvidenceFromHandoff">Request more evidence</button></div>`;
          openDrawer("HANDOFF RECEIVED", `<div class="report-section"><strong>FROM</strong><span>SOC Analyst — Maya Chen</span></div>
            <div class="report-section"><strong>INCIDENT</strong><span>INC-2026-0812</span></div>
            <div class="report-section"><strong>ASSESSMENT</strong><span>Possible successful SQL injection</span></div>
            <div class="report-section"><strong>CONFIDENCE</strong><span>${Math.round(commanderConfidence())}% — Medium</span></div>
            <div class="report-section"><strong>WHAT WE KNOW</strong><span>✓ WAF signature matched<br>✓ Abnormal DB activity<br>? Data exfiltration unconfirmed</span></div>
            <div class="report-section"><strong>WHAT SOC NEEDS FROM YOU</strong><span>Containment decision and stakeholder coordination</span></div>
            <div class="report-section"><strong>RECOMMENDATION</strong><span>Targeted portal containment before full isolation</span></div>
            ${commandActionHtml}`);
          if ($("acceptCommandFromHandoff")) $("acceptCommandFromHandoff").addEventListener("click", () => { applyCommanderDecision("accept"); els.eventDrawer.classList.remove("open"); });
          $("requestEvidenceFromHandoff").addEventListener("click", () => { applyCommanderDecision("more"); els.eventDrawer.classList.remove("open"); });
        } else if (state.role === "AppSec Engineer") {
          openDrawer("SOC → APPSEC HANDOFF", `<div class="report-section"><strong>Finding</strong><span>Suspected SQL injection</span></div>
            <div class="report-section"><strong>Affected endpoint</strong><span>GET /customers?id=</span></div>
            <div class="report-section"><strong>Source</strong><span>198.51.100.24</span></div>
            <div class="report-section"><strong>Observed payload</strong><span>12' UNION SELECT email,password_hash FROM users--</span></div>
            <div class="report-section"><strong>SOC confidence</strong><span>${Math.round(commanderConfidence())}%</span></div>
            <div class="report-section"><strong>Evidence attached</strong><span>WAF-1192, HTTP-8841, DB-8841</span></div>
            <div class="report-section"><strong>Requested action</strong><span>Reproduce exploit, identify root cause, prepare remediation, and request deployment approval.</span></div>
            <div class="ready-row ${state.appsecHandoffAccepted ? "done" : ""}"><span>${state.appsecHandoffAccepted ? "✓" : "?"}</span><span>${state.appsecHandoffAccepted ? "Handoff accepted" : "Accept the handoff in the AppSec workspace."}</span></div>
            <div class="actions"><button class="btn primary" id="openAppsecFromHandoff" type="button">Open AppSec workspace</button></div>`);
          $("openAppsecFromHandoff").addEventListener("click", () => { els.eventDrawer.classList.remove("open"); showPage("appsec"); });
        } else {
          openDrawer("Handoff received", `<div class="report-section"><strong>From</strong><span>SOC Analyst / Incident Automation</span></div>
            <div class="report-section"><strong>Incident</strong><span>INC-2026-0812 / Possible customer portal SQL Injection</span></div>
            <div class="report-section"><strong>Summary</strong><span>Possible successful SQL Injection. Active exploitation suspected, but confidence depends on collected evidence.</span></div>
            <div class="report-section"><strong>Evidence attached</strong><span>${Object.keys(state.collectedEvidence).length ? Object.keys(state.collectedEvidence).join(", ") : "No artifacts attached yet. Start with WAF, HTTP, and DB evidence."}</span></div>
            <div class="report-section"><strong>Your role</strong><span>${roleAccess[state.role].modules.join(", ")}</span></div>`);
        }
        renderAI("next");
      }
      if (!state.loggedIn) {
        const selectedAccount = state.selectedLoginRole ? demoAccounts[state.selectedLoginRole] : null;
        const selectedDetails = selectedAccount ? roleLandingDetails(selectedAccount.role) : null;
        const landingMetrics = [
          ["Risk", state.risk, "%", "Active"],
          ["Evidence", state.evidence, "%", "Building"],
          ["Roles", Object.keys(demoAccounts).length, "", "Ready"],
          ["Signals", phases[0].feed.length, "", "Live"]
        ];
        els.loginPanel.className = "panel login-panel";
        document.body.classList.remove("is-logged-in");
        document.body.classList.remove("is-commander");
        document.body.classList.remove("is-appsec");
        document.body.classList.remove("is-legal");
        delete document.body.dataset.activePage;
        els.loginPanel.innerHTML = `
          <section class="landing-card" aria-label="Choose incident response workspace">
            <h2>Choose your role</h2>
            <p class="landing-intro">Select a workspace to enter the simulation.</p>
            <div class="demo-accounts">${Object.values(demoAccounts).map(account => {
              const details = roleLandingDetails(account.role);
              return `<button class="demo-account ${selectedAccount?.username === account.username ? "selected" : ""}" type="button" data-demo-user="${account.username}" aria-label="Enter ${details.title} workspace"><span class="role-icon">${details.icon}</span><b>${details.title}</b><span class="role-focus">${details.focus}</span><span class="role-arrow">→</span></button>`;
            }).join("")}</div>
            <div class="landing-matrix" id="landingMatrix" aria-label="Live simulator readiness matrix">
              <div class="matrix-row matrix-head"><span>Metric</span><span>Value</span><span>Status</span></div>
              ${landingMetrics.map(metric => `<div class="matrix-row">
                <span>${metric[0]}</span>
                <strong><span class="count-up" data-count-to="${metric[1]}" data-count-suffix="${metric[2]}">0${metric[2]}</span></strong>
                <span><i class="matrix-check" aria-hidden="true">&#10003;</i>${metric[3]}</span>
              </div>`).join("")}
            </div>
          </section>
          ${selectedAccount ? `<div class="login-modal-backdrop" data-login-close>
            <form class="credential-panel login-modal" id="credentialLogin" aria-label="${selectedDetails.title} workspace access">
                <button class="login-modal-close" type="button" data-login-close aria-label="Close access dialog">&times;</button>
                <div class="credential-header"><b>${selectedDetails.title}</b><span class="small">Workspace access required before the role briefing is shown.</span></div>
                <div class="login-field">
                  <label for="loginPassword">Access code</label>
                  <input id="loginPassword" name="password" type="password" autocomplete="current-password" placeholder="Enter training access code">
                </div>
                <div class="credential-actions">
                  <button class="btn primary" type="submit">Open ${selectedDetails.title} workspace</button>
                </div>
                <div class="login-error" id="loginError"></div>
                <p class="landing-hint">Training mode accepts any access code with 4 or more characters.</p>
              </form>
            </div>` : ""}`;
        animateCountUps(els.loginPanel);
        els.loginPanel.querySelectorAll("[data-demo-user]").forEach(button => {
          button.addEventListener("click", () => {
            state.selectedLoginRole = button.dataset.demoUser;
            renderLogin();
          });
        });
        const form = $("credentialLogin");
        if (form && selectedAccount) {
          const passwordInput = $("loginPassword");
          const error = $("loginError");
          form.addEventListener("submit", event => {
            event.preventDefault();
            if (passwordInput.value.trim().length < 4) {
              error.textContent = "Access code must contain at least 4 characters.";
              return;
            }
            enterRole(selectedAccount);
          });
          passwordInput.focus();
          els.loginPanel.querySelectorAll("[data-login-close]").forEach(closeTarget => {
            closeTarget.addEventListener("click", event => {
              if (event.target !== closeTarget && closeTarget.classList.contains("login-modal-backdrop")) return;
              state.selectedLoginRole = null;
              renderLogin();
            });
          });
        }
        return;
      }
      els.loginPanel.className = "panel login-panel signed-in";
      if (els.restart) els.restart.textContent = "Restart current scenario";
      document.body.classList.add("is-logged-in");
      document.body.classList.toggle("is-commander", state.role === "Incident Commander");
      document.body.classList.toggle("is-appsec", state.role === "AppSec Engineer");
      document.body.classList.toggle("is-legal", state.role === "Legal/Compliance");
      const account = state.user || { name: state.role, accessLevel: "Incident Response", shift: "Active", clearance: "IR" };
      els.loginPanel.innerHTML = `
        <div><span class="session-badge">Workspace active</span><p class="small">Welcome, ${account.name}. Role: ${state.role}. Access level: ${account.accessLevel}. Assignment: INC-2026-0812 / Severity HIGH.</p></div>
        <button class="btn ghost" id="switchRoleBtn" type="button">Switch role</button>`;
      $("switchRoleBtn").addEventListener("click", () => {
        clearSavedSession();
        state.loggedIn = false;
        state.user = null;
        state.selectedLoginRole = null;
        renderLogin();
        showPage("roles");
      });
    }
    function renderComms() {
      if (!els.commsGrid) return;
      if (state.role === "Legal/Compliance") {
        const drafts = [
          ["support", "Customer Support draft", "We suffered a data breach and all customer passwords were exposed.", "Request changes", "Facts not confirmed; avoid overstatement.", "CHANGES REQUESTED"],
          ["cto", "CTO request", "Can we publicly say no customer data left the environment?", "Cannot confirm yet", "Evidence does not prove that yet.", "CHANGES REQUESTED"],
          ["pr", "PR holding statement", "We identified suspicious activity affecting our customer portal. Investigation is ongoing.", "Approve with edits", "Matches known facts without overclaiming.", "HOLDING STATEMENT SENT"],
          ["dpo", "DPO briefing", "Prepare a fact pattern, data categories, timeline, and notification recommendation.", "Approve", "Appropriate internal briefing.", "APPROVED"]
        ];
        els.commsGrid.innerHTML = drafts.map(item => `<div class="message-card ${state.legalComms[item[0]] ? "answered" : "urgent"}">
          <b>${item[1]}</b><span>${item[2]}</span>
          ${state.legalComms[item[0]] ? `<span class="status-badge">${state.legalComms[item[0]]}</span>` : ""}
          <div class="actions">
            <button class="btn primary" type="button" data-legal-comms="${item[0]}" data-legal-good="true">${item[3]}</button>
            <button class="btn" type="button" data-legal-comms="${item[0]}" data-legal-good="false">Approve as written</button>
            <button class="btn ghost" type="button" data-legal-comms="${item[0]}" data-legal-good="false">Reject without rationale</button>
          </div>
          <span>${state.legalComms[item[0]] ? "Reviewed: " + state.legalComms[item[0]] : "Awaiting legal review."}</span>
        </div>`).join("");
        els.commsGrid.querySelectorAll("[data-legal-comms]").forEach(button => button.addEventListener("click", () => {
          const item = drafts.find(row => row[0] === button.dataset.legalComms);
          const good = button.dataset.legalGood === "true";
          state.legalComms[item[0]] = good ? item[5] : "RISKY COMMUNICATION";
          state.score += good ? 6 : -5;
          state.risk = clamp(state.risk + (good ? -1 : 4), 0, 100);
          logAction(`Legal reviewed communication: ${item[1]} - ${state.legalComms[item[0]]}`, "Legal/Compliance");
          toast(good ? "Communication reviewed" : "Communication risk", good ? item[4] : "Decision was not supported by rationale/evidence.", good ? "good" : "bad");
          renderComms();
          renderLegal();
          renderReportBuilder();
        }));
        return;
      }
      if (state.role === "Legal/Compliance") {
        const selectedClasses = Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]);
        const legalSubjectsEstimate = state.legalExposureSaved ? "247 confirmed" : selectedClasses.length >= 4 ? "247 likely" : selectedClasses.length >= 2 ? "124 estimated" : "Unknown";
        const legalThresholdStatus = state.legalDecisionRecorded ? "MET" : state.legalExposureSaved || selectedClasses.length >= 3 ? "LIKELY MET" : "NOT YET MET";
        const legalSections = [
          ["classification", "Incident classification", "Personal data breach status and awareness time."],
          ["data", "Data categories", "Personal-data classes involved or excluded."],
          ["subjects", "Data subjects", "Estimated affected population."],
          ["risk", "Risk to individuals", "Likely consequences and severity."],
          ["notification", "Notification decision", "Authority and data-subject posture."],
          ["rationale", "Decision rationale", "Evidence-backed legal reasoning."],
          ["comms", "Communication approval", "Approved wording and rejected overclaims."],
          ["record", "Evidence preserved", "Compliance record and audit trail."],
          ["technical", "Technical evidence supplied by SOC", "HTTP/WAF/DB/IAM facts remain supporting appendix only."]
        ];
        els.evidencePicker.innerHTML = legalSections.map(item => `<button class="evidence-pick ${state.selectedEvidence[item[0]] ? "active" : ""}" type="button" data-legal-report="${item[0]}"><b>${item[1]}</b><span>${item[2]}</span></button>`).join("");
        els.evidencePicker.querySelectorAll("[data-legal-report]").forEach(button => button.addEventListener("click", () => {
          state.selectedEvidence[button.dataset.legalReport] = !state.selectedEvidence[button.dataset.legalReport];
          renderReportBuilder();
        }));
        const legalItems = [
          { label: "Legal handoff accepted", done: state.legalHandoffAccepted, page: "legal", missing: "accept legal handoff" },
          { label: "Data categories classified", done: selectedClasses.length >= 3, page: "legal", missing: "classify personal data" },
          { label: "Exposure assessment saved", done: state.legalExposureSaved, page: "legal", missing: "save exposure assessment" },
          { label: "Notification decision recorded", done: state.legalDecisionRecorded, page: "legal", missing: "record regulatory decision" },
          { label: "Communication reviewed", done: Object.keys(state.legalComms).length >= 2, page: "comms", missing: "review communication drafts" },
          { label: "Compliance evidence preserved", done: state.legalDecisionRecorded && selectedClasses.length >= 3, page: "evidence", missing: "preserve compliance decision chain" }
        ];
        const readiness = Math.round(legalItems.filter(item => item.done).length / legalItems.length * 100);
        state.reportReadiness = readiness;
        if (els.closeIncidentBtn) {
          els.closeIncidentBtn.disabled = readiness < 85;
          els.closeIncidentBtn.textContent = readiness < 85 ? "Legal review locked" : "Issue legal decision";
        }
        const readinessHtml = legalItems.map((item, index) => `<div class="ready-row ${item.done ? "done" : ""}"><span>${item.done ? "✓" : "?"}</span><span>${item.done ? item.label : "Missing: " + item.missing}</span>${item.done ? "" : `<button class="btn ghost" type="button" data-missing-target="${index}">Go</button>`}</div>`).join("");
        els.reportPreview.innerHTML = `
          <h3>Draft Breach Assessment Report</h3>
          ${readiness >= 85 ? `<div class="success-banner"><strong>✓ LEGAL REVIEW COMPLETE</strong><span>Breach classification: ${state.legalBreachStatus} | Notification decision: DOCUMENTED | Communication approved: ${Object.keys(state.legalComms).length >= 2 ? "YES" : "PENDING"} | Evidence preserved: YES | Regulatory package ready: YES</span></div>` : ""}
          <div class="report-section"><strong>Incident classification</strong><span>Personal Data Breach — ${state.legalBreachStatus === "CONFIRMED" ? "Confirmed" : "Suspected / under assessment"}</span></div>
          <div class="report-section"><strong>Awareness time</strong><span>${state.legalClockStartedAt === null ? "Not started" : incidentTime(state.legalClockStartedAt)}</span></div>
          <div class="report-section"><strong>Affected system</strong><span>Customer Portal</span></div>
          <div class="report-section"><strong>Data categories</strong><span>${selectedClasses.length ? selectedClasses.join(", ") : "Unknown"}</span></div>
          <div class="report-section"><strong>Data subjects affected</strong><span>${legalSubjectsEstimate}</span></div>
          <div class="report-section"><strong>Notification threshold</strong><span>${legalThresholdStatus}</span></div>
          <div class="report-section"><strong>Notification decision</strong><span>Authority: ${state.legalAuthorityNotification}; Data subjects: ${state.legalSubjectNotification}</span></div>
          <div class="report-section"><strong>Decision rationale</strong><span>${state.legalRationale || "No rationale recorded yet."}</span></div>
          <div class="report-section"><strong>Technical evidence supplied by SOC</strong><span>HTTP payload, WAF alert, DB audit, IAM events kept as appendix, not legal conclusion by themselves.</span></div>
          <div class="report-section"><strong>Readiness</strong><span>${readiness}% - ${readiness >= 85 ? "ready for legal closure" : "needs legal/compliance work"}</span></div>
          <div class="readiness-list">${readinessHtml}</div>`;
        els.reportPreview.querySelectorAll("[data-missing-target]").forEach(button => button.addEventListener("click", () => {
          const target = legalItems[Number(button.dataset.missingTarget)];
          logAction(`Navigated to Legal report item: ${target.missing}`, "Legal/Compliance");
          showPage(target.page);
        }));
        return;
      }
      if (state.role === "Incident Commander") {
        const questions = [
          ["cto", "CTO", "Do we have confirmed customer data exposure?", ["Yes, breach confirmed.", "Investigation ongoing; exposure not confirmed.", "No customer impact."], 1],
          ["legal", "Legal", "Do we have evidence that triggers notification obligations?", ["Notify immediately.", "Not enough confirmed facts yet.", "No legal review needed."], 1],
          ["support", "Customer Support", "Can we tell customers their data is safe?", ["Yes, data is safe.", "Use holding statement: investigation ongoing.", "Do not respond."], 1],
          ["dev", "Engineering", "Patch ready. Deploy now or wait for forensic snapshot?", ["Deploy immediately.", "Preserve snapshot, then deploy tested patch.", "Wait until tomorrow."], 1]
        ];
        const commsStatus = {
          cto: "Briefed",
          legal: "Legal review requested",
          support: "Holding statement sent",
          dev: "Recovery guidance sent"
        };
        els.commsGrid.innerHTML = questions.map(q => `<div class="message-card ${state.commandComms[q[0]] ? "answered" : "urgent"}">
          <b>${q[1]}</b><span>${q[2]}</span>
          <div class="actions">${q[3].map((answer, index) => `<button class="btn ${index === q[4] ? "primary" : ""}" type="button" data-command-comms="${q[0]}" data-answer-index="${index}">${answer}</button>`).join("")}</div>
          <span>${state.commandComms[q[0]] ? commsStatus[q[0]] + ": " + state.commandComms[q[0]] : "Awaiting commander response."}</span>
        </div>`).join("");
        els.commsGrid.querySelectorAll("[data-command-comms]").forEach(button => button.addEventListener("click", () => {
          const item = questions.find(q => q[0] === button.dataset.commandComms);
          const selected = Number(button.dataset.answerIndex);
          const correct = selected === item[4];
          state.commandComms[item[0]] = item[3][selected];
          state.score += correct ? 8 : -5;
          state.risk = clamp(state.risk + (correct ? -2 : 5), 0, 100);
          logAction(`Commander replied to ${item[1]}: ${item[3][selected]}`, "Incident Commander");
          toast(correct ? "Accurate communication" : "Risky communication", correct ? "Stakeholder confidence improved." : "Message was not supported by evidence.", correct ? "good" : "bad");
          renderComms();
          renderMetrics();
          renderCommanderWarRoom();
          renderReportBuilder();
        }));
        return;
      }
      els.commsGrid.innerHTML = comms.map(message => `<button class="message-card ${message[1]} ${state.answeredMessages[message[0]] ? "answered" : ""}" type="button" data-message="${message[0]}">
        <b>${message[2]}</b><span>${message[3]}</span><span>${state.answeredMessages[message[0]] ? "Answered: " + message[4] : "Click to respond."}</span>
      </button>`).join("");
      els.commsGrid.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => {
          if (!state.answeredMessages[button.dataset.message]) {
            state.answeredMessages[button.dataset.message] = true;
            state.score += 4;
            state.evidence = clamp(state.evidence + 2, 0, 100);
          }
          renderComms();
          renderMetrics();
          renderImpactMonitor();
        });
      });
    }

    function renderReportBuilder() {
      if (!els.evidencePicker) return;
      if (state.role === "AppSec Engineer") {
        const appsecResidualRisk = state.patchDeployed ? "Very Low" : state.patchTested && state.appsecPatchApplied ? "Low" : state.appsecPatchApplied ? "Medium" : "High";
        const remediationSections = [
          ["vuln", "Vulnerability", "SQL Injection in customer portal endpoint."],
          ["component", "Affected component", "Customer Portal / GET /customers."],
          ["root", "Root cause", "Unsanitized input concatenated into SQL query."],
          ["repro", "Exploit reproduced", "Safe lab reproduction and response delta."],
          ["fix", "Fix", "Parameterized query PATCH-204."],
          ["tests", "Security tests", "Regression result and authorization behavior."],
          ["deploy", "Deployment", "Commander approval status."],
          ["risk", "Residual risk", "Remaining risk after remediation."]
        ];
        els.evidencePicker.innerHTML = remediationSections.map(item => `<button class="evidence-pick ${state.selectedEvidence[item[0]] ? "active" : ""}" type="button" data-appsec-report="${item[0]}">
          <b>${item[1]}</b><span>${item[2]}</span>
        </button>`).join("");
        els.evidencePicker.querySelectorAll("[data-appsec-report]").forEach(button => {
          button.addEventListener("click", () => {
            state.selectedEvidence[button.dataset.appsecReport] = !state.selectedEvidence[button.dataset.appsecReport];
            renderReportBuilder();
          });
        });
        const appsecItems = [
          { label: "SOC handoff accepted", done: state.appsecHandoffAccepted, page: "appsec", missing: "accept SOC handoff" },
          { label: "Exploit reproduced safely", done: state.appsecExploitReproduced, page: "appsec", missing: "run safe reproduction lab" },
          { label: "Root cause confirmed", done: state.appsecRootCauseConfirmed, page: "appsec", missing: "confirm vulnerable code path" },
          { label: "Patch created", done: state.appsecPatchApplied, page: "appsec", missing: "apply parameterized query patch" },
          { label: "Regression tests passed", done: state.patchTested, page: "appsec", missing: "run security regression tests" },
          { label: "Deployment requested", done: state.appsecDeploymentRequested || state.patchDeployed, page: "appsec", missing: "send deployment request" },
          { label: "Deployment approved", done: state.patchDeployed, page: "approvals", missing: "wait for Commander approval" }
        ];
        const readiness = Math.round(appsecItems.filter(item => item.done).length / appsecItems.length * 100);
        state.reportReadiness = readiness;
        if (els.closeIncidentBtn) {
          els.closeIncidentBtn.disabled = readiness < 80;
          els.closeIncidentBtn.textContent = readiness < 80 ? "Remediation package locked" : "Submit remediation package";
        }
        const selectedSections = remediationSections.filter(item => state.selectedEvidence[item[0]]).map(item => item[1]);
        const readinessHtml = appsecItems.map((item, index) => `<div class="ready-row ${item.done ? "done" : ""}"><span>${item.done ? "✓" : "?"}</span><span>${item.done ? item.label : "Missing: " + item.missing}</span>${item.done ? "" : `<button class="btn ghost" type="button" data-missing-target="${index}">Go</button>`}</div>`).join("");
        els.reportPreview.innerHTML = `
          <h3>AppSec Remediation Report</h3>
          ${state.patchDeployed ? `<div class="success-banner"><strong>✓ REMEDIATION COMPLETE</strong><span>Exploit no longer reproducible | 3/3 tests passed | Deployment approved | Residual risk: VERY LOW</span></div>` : ""}
          <div class="report-section"><strong>Vulnerability</strong><span>SQL Injection</span></div>
          <div class="report-section"><strong>Affected component</strong><span>Customer Portal / GET /customers?id=</span></div>
          <div class="report-section"><strong>Root cause</strong><span>${state.appsecRootCauseConfirmed ? "Unsanitized input concatenated into SQL query." : "Not confirmed yet."}</span></div>
          <div class="report-section"><strong>Exploit reproduced</strong><span>${state.appsecExploitReproduced ? "Yes, safely reproduced in lab with DB anomaly." : "Not yet."}</span></div>
          <div class="report-section"><strong>Fix</strong><span>${state.appsecPatchApplied ? "PATCH-204: parameterized query." : "No patch applied yet."}</span></div>
          <div class="report-section"><strong>Security tests</strong><span>${state.patchTested ? "3/3 passed." : "Not complete."}</span></div>
          <div class="report-section"><strong>Deployment</strong><span>${state.patchDeployed ? "Approved" : state.appsecDeploymentRequested ? "Pending Incident Commander approval" : "Not requested"}</span></div>
          <div class="report-section"><strong>Residual risk</strong><span>${appsecResidualRisk}</span></div>
          <div class="report-section"><strong>Verify fix</strong><span>${state.patchDeployed ? "Exploit no longer reproducible. Normal traffic preserved. Remediation complete ✓" : "Awaiting deployment approval before production verification."}</span></div>
          <div class="report-section"><strong>Selected sections</strong><span>${selectedSections.length ? selectedSections.join(", ") : "Select remediation report sections."}</span></div>
          <div class="report-section"><strong>Readiness</strong><span>${readiness}% - ${readiness >= 80 ? "ready to submit" : "needs remediation work"}</span></div>
          <div class="readiness-list">${readinessHtml}</div>`;
        els.reportPreview.querySelectorAll("[data-missing-target]").forEach(button => button.addEventListener("click", () => {
          const target = appsecItems[Number(button.dataset.missingTarget)];
          logAction(`Navigated to AppSec report item: ${target.missing}`, "AppSec Engineer");
          toast("Opening required workspace", target.missing);
          showPage(target.page);
        }));
        return;
      }
      if (state.role === "Incident Commander") {
        const executiveSections = [
          ["summary", "Incident summary", "Executive framing of what happened and current confidence."],
          ["business", "Business impact", "Service health, customer impact, downtime, and estimated loss."],
          ["customer", "Customer impact", "What is confirmed, suspected, and unknown."],
          ["timeline", "Decision timeline", "Commander decisions and rationale."],
          ["containment", "Containment decisions", "Actions approved, rejected, or delayed."],
          ["comms", "Stakeholder communications", "CTO, Legal, Support, Engineering coordination."],
          ["legal", "Legal status", "Notification readiness and evidence confidence."],
          ["recovery", "Recovery authorization", "Patch, validation, monitoring, and closure."],
          ["appendix", "Technical appendix supplied by SOC", "HTTP/WAF/DB/IAM evidence attached as supporting material."]
        ];
        els.evidencePicker.innerHTML = executiveSections.map(item => `<button class="evidence-pick ${state.selectedEvidence[item[0]] ? "active" : ""}" type="button" data-exec-section="${item[0]}">
          <b>${item[1]}</b><span>${item[2]}</span>
        </button>`).join("");
        els.evidencePicker.querySelectorAll("[data-exec-section]").forEach(button => {
          button.addEventListener("click", () => {
            state.selectedEvidence[button.dataset.execSection] = !state.selectedEvidence[button.dataset.execSection];
            renderReportBuilder();
          });
        });
      } else {
      els.evidencePicker.innerHTML = reportEvidence.map(item => `<button class="evidence-pick ${state.selectedEvidence[item[0]] ? "active" : ""}" type="button" data-evidence="${item[0]}">
        <b>${item[1]}</b><span>${item[2]}</span>
      </button>`).join("");
      els.evidencePicker.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => {
          state.selectedEvidence[button.dataset.evidence] = !state.selectedEvidence[button.dataset.evidence];
          state.evidence = clamp(state.evidence + (state.selectedEvidence[button.dataset.evidence] ? 3 : -3), 0, 100);
          renderReportBuilder();
          renderMetrics();
        });
      });
      }
      const selected = reportEvidence.filter(item => state.selectedEvidence[item[0]]);
      const collectedCount = Object.keys(state.collectedEvidence).length;
      if (state.role === "Incident Commander") {
        const selectedExecutiveSections = [
          ["summary", "Incident summary"],
          ["business", "Business impact"],
          ["customer", "Customer impact"],
          ["timeline", "Decision timeline"],
          ["containment", "Containment decisions"],
          ["comms", "Stakeholder communications"],
          ["legal", "Legal status"],
          ["recovery", "Recovery authorization"],
          ["appendix", "Technical appendix supplied by SOC"]
        ].filter(item => state.selectedEvidence[item[0]]);
        const socAppendix = collectedCount
          ? evidenceGameRows.filter(row => state.collectedEvidence[row.id]).slice(0, 5).map(row => `${row.id} ${row.source}`).join(", ")
          : "SOC has not attached validated artifacts yet";
        const commanderItems = [
          { label: "Incident summary", done: state.commanderAccepted || state.loggedIn, page: "warroom", missing: "accept incident command" },
          { label: "Business impact", done: true, page: "warroom", missing: "review business impact" },
          { label: "Customer impact", done: state.recordsExposed !== null || state.collectedEvidence["E-007"] || Object.keys(state.commandComms).length > 0, page: "comms", missing: "coordinate customer/support update" },
          { label: "Decision timeline", done: state.actionTimeline.some(item => item.actor.includes("Commander")), page: "warroom", missing: "record commander decision" },
          { label: "Containment decisions", done: state.commandDecision || state.containmentTime !== null, page: "approvals", missing: "approve or request containment decision" },
          { label: "Communications", done: Object.keys(state.commandComms).length >= 2, page: "comms", missing: "brief stakeholders" },
          { label: "Legal assessment", done: state.commandComms.legal || state.legalAnswer, page: "comms", missing: "coordinate legal assessment with Legal" },
          { label: "Recovery status", done: state.patchDeployed || state.phase >= 3, page: "inbox", missing: "request recovery update from AppSec/Engineering" },
          { label: "Lessons learned", done: state.reportReadiness >= 80, page: "reportbuilder", missing: "complete executive report readiness" }
        ];
        const readiness = Math.round(commanderItems.filter(item => item.done).length / commanderItems.length * 100);
        state.reportReadiness = readiness;
        if (els.closeIncidentBtn) {
          els.closeIncidentBtn.disabled = readiness < 80;
          els.closeIncidentBtn.textContent = readiness < 80 ? "Executive closure locked" : "Close incident";
        }
        const readinessHtml = commanderItems.map((item, index) => `<div class="ready-row ${item.done ? "done" : ""}"><span>${item.done ? "✓" : "?"}</span><span>${item.done ? item.label : "Missing: " + item.missing}</span>${item.done ? "" : `<button class="btn ghost" type="button" data-missing-target="${index}">Go</button>`}</div>`).join("");
        els.reportPreview.innerHTML = `
          <h3>Executive Incident Report</h3>
          <div class="report-section"><strong>Role owner</strong><span>Incident Commander</span></div>
          <div class="report-section"><strong>Incident summary</strong><span>Customer portal SQL Injection incident. SOC confidence ${Math.round(commanderConfidence())}%. Data exposure ${state.recordsExposed === null ? "unconfirmed" : state.recordsExposed.toLocaleString() + " records"}.</span></div>
          <div class="report-section"><strong>Business impact</strong><span>Service health ${state.serviceHealth}%, risk ${state.risk}%, estimated loss ${money(state.loss)}.</span></div>
          <div class="report-section"><strong>Selected executive sections</strong><span>${selectedExecutiveSections.length ? selectedExecutiveSections.map(item => item[1]).join(", ") : "Select the sections the executive report should include."}</span></div>
          <div class="report-section"><strong>Decision timeline</strong><span>${state.actionTimeline.filter(item => item.actor.includes("Commander") || item.action.includes("Approved") || item.action.includes("Requested")).slice(-6).map(item => `${item.time} ${item.actor}: ${item.action}`).join("<br>") || "No commander decision recorded yet."}</span></div>
          <div class="report-section"><strong>Technical appendix</strong><span>Supplied by SOC: ${socAppendix}</span></div>
          <div class="report-section"><strong>Executive readiness</strong><span>${readiness}% - ${readiness >= 80 ? "ready for closure" : "needs commander actions"}</span></div>
          <div class="readiness-list">${readinessHtml}</div>`;
        els.reportPreview.querySelectorAll("[data-missing-target]").forEach(button => button.addEventListener("click", () => {
          const target = commanderItems[Number(button.dataset.missingTarget)];
          logAction(`Navigated to commander report item: ${target.missing}`, "Incident Commander");
          toast("Opening required workspace", target.missing);
          showPage(target.page);
        }));
        return;
      }
      const readinessItems = [
        { label: "Incident classification", done: state.loggedIn, page: "inbox", missing: "classify the SOC alert" },
        { label: "Timeline", done: state.terminalLines.some(line => line.includes("09:12 WAF")) || state.phase > 0 || state.actionTimeline.length > 2, page: "warroom", missing: "run timeline or record actions" },
        { label: "Attack vector", done: state.evidence >= 25 || state.collectedEvidence["E-003"], page: "evidence", evidenceId: "E-003", missing: "collect HTTP exploit evidence" },
        { label: "Affected assets", done: state.attackerProgress >= 20 || state.collectedEvidence["E-005"], page: "evidence", evidenceId: "E-005", missing: "confirm DB/application impact" },
        { label: "Data exposure", done: state.recordsExposed !== null || state.evidence >= 55, page: "evidence", evidenceId: "E-008", missing: "collect DB/egress/customer evidence" },
        { label: "Containment actions", done: state.appliedRecs.contain || state.risk < 35 || state.containmentTime !== null, page: "approvals", missing: "request or execute containment" },
        { label: "Root cause", done: selected.some(item => item[0] === "patch") || state.patchTested || state.phase >= 2, page: "appsec", missing: "inspect code and validate patch" },
        { label: "Recovery verification", done: state.phase >= 3 || state.patchDeployed, page: "appsec", missing: "deploy/verify recovery" }
      ];
      const readiness = Math.round(readinessItems.filter(item => item.done).length / readinessItems.length * 100);
      state.reportReadiness = readiness;
      const quality = Math.min(100, selected.length * 10 + collectedCount * 8 + readiness * .45);
      const readinessHtml = readinessItems.map((item, index) => `<div class="ready-row ${item.done ? "done" : ""}" title="${item.done ? "Complete" : "Missing: " + item.missing}"><span>${item.done ? "✓" : "?"}</span><span>${item.done ? item.label : "Missing: " + item.missing}</span>${item.done ? "" : `<button class="btn ghost" type="button" data-missing-target="${index}">Go</button>`}</div>`).join("");
      if (els.closeIncidentBtn) {
        els.closeIncidentBtn.disabled = readiness < 80;
        els.closeIncidentBtn.textContent = readiness < 80 ? "Close incident locked" : "Close incident";
      }
      els.reportPreview.innerHTML = `
        <h3>Draft Incident Report</h3>
        <div class="report-section"><strong>Role owner</strong><span>${state.role}</span></div>
        <div class="report-section"><strong>Executive summary</strong><span>SQL Injection in customer portal created possible customer-data exposure. Current risk ${state.risk}%.</span></div>
        <div class="report-section"><strong>Included evidence</strong><span>${selected.length ? selected.map(item => item[1]).join(", ") : "No evidence selected yet."}</span></div>
        <div class="report-section"><strong>Live timeline</strong><span>${state.actionTimeline.slice(-5).map(item => `${item.time} ${item.actor}: ${item.action}`).join("<br>")}</span></div>
        <div class="report-section"><strong>Report readiness</strong><span>${readiness}% - ${readiness >= 80 ? "incident can be closed" : "cannot close incident yet"}</span></div>
        <div class="readiness-list">${readinessHtml}</div>
        <div class="report-section"><strong>Report quality</strong><span>${Math.round(quality)}% - ${quality > 75 ? "ready for review" : quality > 40 ? "needs more evidence" : "too weak for leadership/legal"}</span></div>`;
      els.reportPreview.querySelectorAll("[data-missing-target]").forEach(button => button.addEventListener("click", () => {
        const target = readinessItems[Number(button.dataset.missingTarget)];
        logAction(`Navigated to missing report item: ${target.missing}`);
        if (target.evidenceId) {
          state.highlightEvidenceId = target.evidenceId;
          state.selectedEvidenceRow = target.evidenceId;
          state.evidenceFilter = "all";
        }
        showPage(target.page);
      }));
    }

    function generateRoleReport() {
      const selected = reportEvidence.filter(item => state.selectedEvidence[item[0]]);
      const appsecResidualRisk = state.patchDeployed ? "Very Low" : state.patchTested && state.appsecPatchApplied ? "Low" : state.appsecPatchApplied ? "Medium" : "High";
      const selectedExecutiveSections = [
        ["summary", "Incident summary"],
        ["business", "Business impact"],
        ["customer", "Customer impact"],
        ["timeline", "Decision timeline"],
        ["containment", "Containment decisions"],
        ["comms", "Stakeholder communications"],
        ["legal", "Legal status"],
        ["recovery", "Recovery authorization"],
        ["appendix", "Technical appendix supplied by SOC"]
      ].filter(item => state.selectedEvidence[item[0]]);
      const reportTone = state.role === "Legal/Compliance" ? "Legal/Compliance Incident Assessment" :
        state.role === "AppSec Engineer" ? "Application Security Remediation Report" :
        state.role === "Incident Commander" ? "Incident Command Executive Report" :
        "SOC Technical Incident Report";
      const roleFocus = state.role === "Legal/Compliance" ? "confirmed facts, data classes, unknowns, and notification readiness" :
        state.role === "AppSec Engineer" ? "root cause, patch validation, secure coding controls, and regression prevention" :
        state.role === "Incident Commander" ? "timeline, owners, business impact, containment status, and executive decisions" :
        "alert correlation, indicators, evidence preservation, and containment telemetry";
      const dynamicTimeline = state.actionTimeline.map(item => `${item.time} ${item.actor}: ${item.action}`).join("<br>");
      const collected = evidenceGameRows.filter(row => state.collectedEvidence[row.id]);
      els.generatedReport.innerHTML = `
        <div class="generated-report">
          <span class="stamp">GENERATED FROM LIVE INCIDENT STATE</span>
          <h3>${reportTone} ${state.reportReadiness < 80 ? "(DRAFT - INCOMPLETE)" : "(READY FOR CLOSURE)"}</h3>
          <p><strong>Incident:</strong> SQL Injection in customer portal after CTF flag discovery.</p>
          <p><strong>Prepared by role:</strong> ${state.role}. This report emphasizes ${roleFocus}.</p>
          <h4>Executive summary</h4>
          <p>The customer portal was confirmed vulnerable to SQL Injection. Current measured risk is ${state.risk}%, evidence quality is ${state.evidence}%, and estimated business loss is ${money(state.loss)}.</p>
          ${state.role === "Incident Commander" ? `<h4>Executive report sections</h4>
          <p>${selectedExecutiveSections.length ? selectedExecutiveSections.map(item => item[1]).join(", ") : "No executive sections selected yet."}</p>
          <h4>Command decisions</h4>
          <p>${state.actionTimeline.filter(item => item.actor.includes("Commander") || item.action.includes("Approved") || item.action.includes("Rejected")).slice(-8).map(item => `${item.time} ${item.actor}: ${item.action}`).join("<br>") || "No command decisions recorded yet."}</p>` : ""}
          ${state.role === "AppSec Engineer" ? `<h4>Remediation package</h4>
          <p><strong>Vulnerability:</strong> SQL Injection<br>
          <strong>Affected endpoint:</strong> GET /customers?id=<br>
          <strong>Root cause:</strong> ${state.appsecRootCauseConfirmed ? "Unsanitized input concatenated into SQL query." : "Not confirmed yet."}<br>
          <strong>Exploit reproduced:</strong> ${state.appsecExploitReproduced ? "Yes" : "No"}<br>
          <strong>Fix:</strong> ${state.appsecPatchApplied ? "PATCH-204 parameterized query" : "Not applied"}<br>
          <strong>Security tests:</strong> ${state.patchTested ? "3/3 passed" : "Not complete"}<br>
          <strong>Deployment:</strong> ${state.patchDeployed ? "Approved" : state.appsecDeploymentRequested ? "Pending Commander approval" : "Not requested"}<br>
          <strong>Residual risk:</strong> ${appsecResidualRisk}</p>` : ""}
          ${state.role === "Legal/Compliance" ? `<h4>Compliance package</h4>
          <p><strong>Classification:</strong> Personal Data Breach — ${state.legalBreachStatus === "CONFIRMED" ? "Confirmed" : "Under assessment"}<br>
          <strong>Data categories:</strong> ${Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]).join(", ") || "Unknown"}<br>
          <strong>Data subjects:</strong> ${state.legalExposureSaved ? "247 confirmed" : "Unknown"}<br>
          <strong>Risk to individuals:</strong> ${state.legalRiskLevel}<br>
          <strong>Authority notification:</strong> ${state.legalAuthorityNotification}<br>
          <strong>Data-subject communication:</strong> ${state.legalSubjectNotification}<br>
          <strong>Rationale:</strong> ${state.legalRationale || "Not recorded yet."}</p>` : ""}
          <h4>Evidence included</h4>
          <p>${state.role === "Incident Commander" ? "Technical appendix supplied by SOC for executive review." : state.role === "AppSec Engineer" ? "HTTP payload, application trace, generated SQL behavior, code diff, and regression results." : state.role === "Legal/Compliance" ? "Incident facts, personal-data classification, exposure assessment, communication approvals, and legal decision rationale." : selected.length ? selected.map(item => `${item[1]}: ${item[2]}`).join(" ") : "No evidence selected. Report is not ready for review."}</p>
          <h4>Collected artifacts</h4>
          <p>${collected.length ? collected.map(row => `${row.id} ${row.source} (${row.confidence}) collected ${row.time}, integrity SHA-256 verified.`).join(" ") : "No chain-of-custody artifacts collected yet."}</p>
          <h4>Timeline</h4>
          <p>${dynamicTimeline || "No live actions recorded yet."}</p>
          <h4>Actions taken</h4>
          <p>${state.history.length ? state.history.map(item => item.choice).join("; ") : "No major response decisions recorded yet."}</p>
          <h4>Recommended next step</h4>
          <p>${state.evidence < 50 ? "Preserve more evidence before final legal or executive sign-off." : state.risk > 45 ? "Prioritize containment validation and monitoring." : "Proceed to final review, lessons learned, and durable remediation tracking."}</p>
        </div>`;
    }

    function renderKillLab() {
      const detail = killChainDetails[state.selectedKillStep] || killChainDetails[0];
      const sim = killChainSims[state.selectedKillStep] || killChainSims[0];
      if (els.killLabDetail) {
        els.killLabDetail.innerHTML = `<strong>${detail[0]}</strong><p class="small">${detail[1]}</p>`;
      }
      if (els.killSimText) els.killSimText.textContent = sim.text;
      if (els.phaseVisualTitle) els.phaseVisualTitle.textContent = `${detail[0]} visual simulation`;
      if (els.phaseVisualMetric) {
        const metrics = ["routes probed", "payload confirmed", "tables mapped", "controls active", "report ready"];
        els.phaseVisualMetric.textContent = metrics[state.selectedKillStep] || "live signal";
      }
      if (els.toolChain) {
        els.toolChain.innerHTML = sim.tools.map((tool, index) => `<div class="tool-step">
          <span class="tool-icon">${index + 1}</span>
          <div><b>${tool[0]}</b><p>${tool[1]}</p></div>
        </div>`).join("");
      }
      renderRealScene();
    }

    function showPage(page) {
      if (!state.loggedIn) page = "roles";
      if (state.loggedIn && page === "roles") page = roleAccess[state.role].home;
      if (state.loggedIn && !roleAccess[state.role].pages.includes(page)) page = roleAccess[state.role].home;
      if (state.loggedIn && state.role === "SOC Analyst" && page === "wafalert" && !state.wafAlertOpened) {
        state.wafAlertOpened = true;
        logAction("Opened WAF alert investigation workspace");
      }
      document.body.dataset.activePage = page;
      document.querySelectorAll(".nav-btn").forEach(button => {
        const allowed = state.loggedIn && roleAccess[state.role].pages.includes(button.dataset.page);
        button.classList.toggle("is-hidden-for-role", !allowed);
        button.classList.toggle("active", button.dataset.page === page);
      });
      if (els.inboxNavBtn) els.inboxNavBtn.textContent = state.role === "Incident Commander" ? "Incident Updates" : "SOC Inbox";
      if (els.warRoomNavBtn) els.warRoomNavBtn.textContent = "Dashboard";
      if (els.reportBuilderNavBtn) els.reportBuilderNavBtn.textContent = state.role === "AppSec Engineer" ? "Remediation Report" : state.role === "Legal/Compliance" ? "Compliance Report" : "Report Builder";
      if (els.aiPanelTitle) els.aiPanelTitle.textContent = state.role === "AppSec Engineer" ? "AI AppSec Assistant" : state.role === "Legal/Compliance" ? "AI Legal / Compliance Assistant" : state.role === "Incident Commander" ? "AI Command Advisor" : "AI Incident Copilot";
      if (els.reportBuilderTitle) els.reportBuilderTitle.textContent = state.role === "AppSec Engineer" ? "Remediation Report" : state.role === "Legal/Compliance" ? "Compliance Report" : state.role === "Incident Commander" ? "Executive Report Builder" : "Incident Report Builder";
      if (els.reportBuilderIntro) els.reportBuilderIntro.textContent = state.role === "AppSec Engineer" ? "Generate the remediation package from reproduction, code trace, patch diff, test results, and deployment approval." : state.role === "Legal/Compliance" ? "Generate the breach assessment, notification decision, rationale, communication approval, and compliance evidence record." : "Generate the report directly from the current role, selected evidence, incident timeline, and decisions.";
      if (els.livePacketLabel) els.livePacketLabel.textContent = state.role === "Legal/Compliance" ? "Incident status" : "Packet stream";
      if (els.liveSiemLabel) els.liveSiemLabel.textContent = state.role === "Legal/Compliance" ? "Data exposure" : "SIEM correlation";
      if (els.liveDbLabel) els.liveDbLabel.textContent = state.role === "Legal/Compliance" ? "Regulatory status" : "DB audit";
      if (els.liveResponderLabel) els.liveResponderLabel.textContent = state.role === "Legal/Compliance" ? "Communications" : "Responder action";
      if (els.inboxTitle) els.inboxTitle.textContent = state.role === "Incident Commander" ? "Incident Updates" : "SOC Inbox";
      if (els.inboxIntro) els.inboxIntro.textContent = state.role === "Incident Commander" ? "Risk-coded team briefings from SOC, DB, AppSec, Support, and stakeholders. Open each update to acknowledge, request more detail, or assign owners." : "Risk-coded alert queue. Open high-risk items first, investigate supporting signals, and dismiss false positives only when evidence supports it.";
      if (els.evidenceGameTitle) els.evidenceGameTitle.textContent = state.role === "AppSec Engineer" ? "AppSec Evidence Chain" : "Evidence Collection Game";
      if (els.evidenceGameTitle && state.role === "Legal/Compliance") els.evidenceGameTitle.textContent = "Compliance Decision Chain";
      if (els.evidenceTimelineTitle) els.evidenceTimelineTitle.textContent = state.role === "Legal/Compliance" ? "Compliance Evidence Timeline" : "Evidence Timeline";
      if (els.evidenceGameIntro) els.evidenceGameIntro.textContent = state.role === "AppSec Engineer" ? "Follow the technical chain from exploit payload to application code, SQL behavior, patch diff, and regression results." : state.role === "Legal/Compliance" ? "Preserve the decision chain from security incident to personal data, exposure, notification threshold, legal decision, and communication approval." : "Find suspicious events and add them to the case. Evidence collected here improves report readiness.";
      document.querySelectorAll(".page-section").forEach(section => {
        section.classList.toggle("active", section.dataset.pageSection === page);
      });
      if (page === "killlab") {
        state.visualView = "killchain";
        renderKillLab();
        renderKillGame();
      }
      if (page === "inbox") renderSocInbox();
      if (page === "appsec") renderAppSec();
      if (page === "legal") renderLegal();
      if (page === "approvals") renderApprovals();
      if (page === "roles") renderRoles();
      if (page === "comms") renderComms();
      if (page === "evidence") {
        if (state.role === "AppSec Engineer" && !["Code", "App Trace", "DB Query", "Patch Evidence"].includes(state.activeTab)) state.activeTab = "Code";
        if (state.role === "Legal/Compliance" && !["Incident Facts", "Personal Data", "Exposure", "Business Impact", "Legal Record"].includes(state.activeTab)) state.activeTab = "Incident Facts";
        renderEvidence();
        renderEvidenceTimeline();
        if (state.highlightEvidenceId) state.selectedEvidenceRow = state.highlightEvidenceId;
        renderEvidenceGame();
      }
      if (page === "reportbuilder") renderReportBuilder();
      if (page === "ai") renderAI("next");
      if (page === "warroom" && state.role === "Incident Commander") renderCommanderWarRoom();
      if (page === "warroom" && state.role === "AppSec Engineer") renderAppSec();
      renderObjective();
      renderPhases();
    }

    function renderInvestigation() {
      els.investigationGrid.innerHTML = investigations.map(action => {
        const done = Boolean(state.checks[action.id]);
        return `<button class="mini-action ${done ? "done" : ""}" type="button" data-check="${action.id}" ${done ? "disabled" : ""}>
          <strong>${done ? "Done: " : ""}${action.label}</strong>
          <span>${action.desc}</span>
        </button>`;
      }).join("");
      els.investigationGrid.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => runInvestigation(button.dataset.check));
      });
    }

    function runInvestigation(id) {
      if (state.checks[id]) return;
      const action = investigations.find(item => item.id === id);
      if (!action) return;
      state.checks[id] = true;
      state.score += action.score;
      state.risk = clamp(state.risk + action.risk, 0, 100);
      state.evidence = clamp(state.evidence + action.evidence, 0, 100);
      els.investigationNote.textContent = action.note;
      renderMetrics();
      renderImpactMonitor();
      renderAI("next");
      renderInvestigation();
    }

    function renderChoices() {
      els.choices.innerHTML = current().choices.map((choice, index) => `<button class="btn choice" type="button" data-index="${index}">
        <strong>${choice.label}</strong>
        <span>${choice.desc}</span>
      </button>`).join("");
      els.choices.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => choose(Number(button.dataset.index), button));
      });
    }

    function renderPhase() {
      const phase = current();
      els.clock.textContent = phase.time;
      els.phaseTitle.textContent = phase.title;
      els.phaseTags.innerHTML = phase.tags.map(tag => `<span class="pill">${tag}</span>`).join("");
      els.story.innerHTML = `<p>${phase.story}</p>`;
      els.translation.textContent = phase.translation;
      els.attackBadge.textContent = state.risk > 62 ? "ACTIVE BREACH" : state.risk < 25 ? "CONTAINING" : "LIVE EXPLOIT";
      els.outcome.className = "outcome";
      els.outcome.innerHTML = "";
      els.next.disabled = true;
      els.next.textContent = state.phase === phases.length - 1 ? "Close incident" : "Continue incident";
      state.selected = false;
      state.activeTab = "";
      state.activeEvent = 0;
      renderChoices();
      renderEvidence();
      renderFeed();
      renderInvestigation();
      renderPhases();
      renderBriefing();
      renderImpactMonitor();
      renderMetrics();
      renderAI("next");
      renderViewButtons();
      renderNodeInspector();
      typeText(els.flagTerminal, phase.terminal);
      typeText(els.miniTerminal, phase.mini);
    }

    function choose(index, button) {
      if (state.selected) return;
      const choice = current().choices[index];
      state.selected = true;
      state.score += choice.score;
      state.risk = clamp(state.risk + choice.risk, 0, 100);
      state.evidence = clamp(state.evidence + choice.evidence, 0, 100);
      state.loss += choice.loss;
      state.history[state.phase] = {
        phase: current().title,
        choice: choice.label,
        outcome: choice.outcome,
        tone: choice.tone
      };
      els.choices.querySelectorAll("button").forEach(item => item.disabled = true);
      button.classList.add("selected", choice.tone);
      const icon = choice.tone === "good" ? "✓" : choice.tone === "warn" ? "!" : "×";
      els.outcome.className = `outcome show ${choice.tone}`;
      els.outcome.innerHTML = `<h3>${icon} ${choice.label}</h3><p>${choice.outcome}</p>`;
      els.next.disabled = false;
      els.attackBadge.textContent = state.risk > 62 ? "ACTIVE BREACH" : state.risk < 25 ? "CONTAINING" : "LIVE EXPLOIT";
      renderMetrics();
      renderImpactMonitor();
      renderAI("next");
      renderPhases();
      renderObjective();
    }

    function next() {
      if (!state.selected) return;
      if (!state.history[state.phase]) {
        toast("Phase locked", "Make a response decision before moving to the next incident phase.", "bad");
        return;
      }
      if (state.phase < phases.length - 1) {
        state.phase += 1;
        renderPhase();
        window.scrollTo({ top: 0, behavior: "smooth" });
      } else {
        showReport();
      }
    }

    function grade() {
      if (state.score >= 95 && state.risk <= 25 && state.evidence >= 55) {
        return ["Incident contained", "You handled the CTF finding like a real incident: escalation, evidence, scope, containment, reporting, and durable fixes."];
      }
      if (state.score >= 45 && state.risk <= 55) {
        return ["Partial containment", "You controlled the incident, but some decisions increased risk, cost, or uncertainty."];
      }
      return ["Major incident", "Weak decisions turned the technical exploit into a larger business, legal, and recovery problem."];
    }

    function incidentJourneyItems() {
      const socValidated = state.inboxStatuses.waf === "INVESTIGATING" || state.inboxStatuses.waf === "ESCALATED" || Boolean(state.collectedEvidence["E-003"]);
      const scoped = socScoped();
      const commanderDecision = state.commanderAccepted || Boolean(state.commandDecision) || state.approvals.some(item => item.status === "approved");
      const appsecRemediated = state.appsecHandoffAccepted && state.appsecExploitReproduced && state.appsecRootCauseConfirmed && state.patchTested;
      const deploymentApproved = state.patchDeployed || state.approvals.some(item => item.type.includes("PATCH-204") && item.status === "approved");
      const legalComplete = state.legalHandoffAccepted && state.legalExposureSaved && state.legalDecisionRecorded && Object.keys(state.legalComms).length >= 2;
      const closureReady = closureBlockers().length === 0 && state.reportReadiness >= (state.role === "Legal/Compliance" ? 85 : 80);
      return [
        ["CTF evidence", true, "flag{union_select_customer_dump} becomes INC-2026-0812."],
        ["SOC validation", socValidated, socValidated ? "WAF/HTTP evidence links the flag to a real customer portal alert." : "Open the WAF alert and preserve the exploit request."],
        ["SOC scoping", scoped, scoped ? "HTTP, WAF, and DB evidence support a defensible timeline." : "Collect HTTP, WAF, and DB evidence before declaring scope."],
        ["Command decision", commanderDecision, commanderDecision ? "Incident command has accepted ownership or approved a response decision." : "Commander still needs an evidence-backed containment decision."],
        ["AppSec remediation", appsecRemediated, appsecRemediated ? "Exploit reproduced, root cause confirmed, patch tested." : "AppSec needs reproduction, code trace, patch, and tests."],
        ["Deployment approval", deploymentApproved, deploymentApproved ? "PATCH-204 is approved/deployed with monitoring." : "Patch deployment still needs commander approval."],
        ["Legal assessment", legalComplete, legalComplete ? "Data classes, threshold, rationale, and communications are documented." : "Legal needs exposure assessment, decision rationale, and comms approval."],
        ["Final closure", closureReady, closureReady ? "Exploit validation, monitoring, recovery authorization, legal disposition, and report readiness are complete." : "Final closure waits for monitoring, recovery authorization, legal disposition, and report readiness."]
      ];
    }

    function showReport() {
      const [title, text] = grade();
      const decisions = state.history.length ? state.history : [{ choice: "No decisions made", outcome: "The simulation was closed before the incident was handled." }];
      const journey = incidentJourneyItems();
      const journeyComplete = Math.round(journey.filter(item => item[1]).length / journey.length * 100);
      const competencies = [
        ["Detection", clamp(95 - state.attackerProgress * .25, 0, 100)],
        ["Investigation", clamp(state.evidence + Object.keys(state.collectedEvidence).length * 6, 0, 100)],
        ["Evidence Preservation", clamp(state.evidence + (state.terminalLines.some(line => line.includes("snapshot")) ? 15 : 0), 0, 100)],
        ["Containment", clamp(100 - state.risk, 0, 100)],
        ["Communication", clamp(Object.keys(state.answeredMessages).length * 22 + (state.approvals.length ? 10 : 0), 0, 100)],
        ["Recovery", clamp(state.patchDeployed ? 88 : state.patchTested ? 65 : 35, 0, 100)],
        ["Reporting", clamp(Object.keys(state.selectedEvidence).length * 12 + state.evidence * .45, 0, 100)]
      ];
      const finalScore = Math.round(competencies.reduce((sum, item) => sum + item[1], 0) / competencies.length * 10);
      const socScore = Math.round(finalScore / 10);
      const exposed = state.recordsExposed === null ? 0 : state.recordsExposed;
      const didWell = competencies.filter(item => item[1] >= 75).map(item => item[0]);
      const missed = competencies.filter(item => item[1] < 60).map(item => item[0]);
      const attackerStory = state.actionTimeline.filter(item => item.actor === "Telemetry").map(item => `${item.time}: ${item.action}`);
      const riskRaised = decisions.filter(item => item.tone === "bad" || item.tone === "warn").map(item => item.choice);
      const riskReduced = decisions.filter(item => item.tone === "good").map(item => item.choice);
      const missedEvidence = evidenceGameRows.filter(row => row.suspicious && !state.collectedEvidence[row.id]).map(row => `${row.id} ${row.source}`);
      const detectedAt = state.incidentClock.detectedAt ?? state.detectedTime;
      const mttd = duration(detectedAt);
      const mtta = durationBetween(detectedAt, state.incidentClock.acknowledgedAt);
      const mttc = durationBetween(detectedAt, state.incidentClock.containedAt ?? state.containmentTime);
      const mttr = durationBetween(detectedAt, state.incidentClock.recoveredAt);
      const downtimeSeconds = Math.max(0, Math.round((100 - state.serviceHealth) * 14));
      const finalStatus = journeyComplete === 100 ? "CLOSED" : state.risk <= 35 || state.patchDeployed ? "RESOLVED - PENDING WORKSTREAMS" : title.toUpperCase();
      els.report.className = "panel report show";
      els.report.innerHTML = `
        <h2>INC-2026-0812 — ${finalStatus}</h2>
        <p class="small">${text} The flag was not the finish line; it became the first signal of a real incident workflow.</p>
        <div class="report-grid">
          <div class="card metric"><span class="small">SOC Analyst Score</span><strong>${socScore}/100</strong></div>
          <div class="card metric"><span class="small">Final risk</span><strong>${state.risk}%</strong></div>
          <div class="card metric"><span class="small">Evidence quality</span><strong>${state.evidence}%</strong></div>
          <div class="card metric"><span class="small">Cross-role completion</span><strong>${journeyComplete}%</strong></div>
          <div class="card metric"><span class="small">Records accessed</span><strong>${exposed ? exposed.toLocaleString() : "Unknown"}</strong></div>
          <div class="card metric"><span class="small">MTTD</span><strong>${mttd}</strong></div>
          <div class="card metric"><span class="small">MTTA</span><strong>${mtta}</strong></div>
          <div class="card metric"><span class="small">MTTC</span><strong>${mttc}</strong></div>
          <div class="card metric"><span class="small">MTTR</span><strong>${mttr}</strong></div>
          <div class="card metric"><span class="small">Service downtime</span><strong>${duration(downtimeSeconds)}</strong></div>
        </div>
        <div class="card lessons">
          <h3>Incident Scorecard</h3>
          <div class="report-grid">
            <div class="card metric"><span class="small">Detection</span><strong>${Math.round(competencies[0][1])}/100</strong></div>
            <div class="card metric"><span class="small">Investigation</span><strong>${Math.round(competencies[1][1])}/100</strong></div>
            <div class="card metric"><span class="small">Evidence handling</span><strong>${Math.round(competencies[2][1])}/100</strong></div>
            <div class="card metric"><span class="small">Containment</span><strong>${Math.round(competencies[3][1])}/100</strong></div>
            <div class="card metric"><span class="small">False-positive handling</span><strong>${state.inboxStatuses.travel === "DISMISSED" || state.inboxStatuses.powershell === "DISMISSED" ? "85" : "68"}/100</strong></div>
            <div class="card metric"><span class="small">Without intervention</span><strong>18,420 records / €92k</strong></div>
          </div>
          <div class="readiness-list">${competencies.map(item => `<div class="ready-row ${item[1] >= 75 ? "done" : ""}"><span>${item[1] >= 75 ? "✓" : "!"}</span><span>${item[0]} ${Math.round(item[1])}</span></div>`).join("")}</div>
        </div>
        <div class="card lessons">
          <h3>CTF vs Real World</h3>
          <p><strong>CTF:</strong> Find SQLi → exploit → get flag → challenge complete.</p>
          <p><strong>REAL WORLD:</strong> Alert → validate → scope → preserve evidence → contain → recover → report.</p>
          <p><strong>Transition:</strong> flag{union_select_customer_dump} → INC-2026-0812 → SOC investigation → Commander decision → AppSec remediation → Legal assessment → incident closure.</p>
        </div>
        <div class="card lessons">
          <h3>Incident Closure Summary</h3>
          <p><strong>Company:</strong> Northstar Digital Services<br>
          <strong>System:</strong> customer-portal-prod<br>
          <strong>Severity:</strong> HIGH<br>
          <strong>Initial detection:</strong> WAF alert for SQL injection against GET /customers?id=<br>
          <strong>Root cause:</strong> Unsanitized user-controlled input concatenated into a database query.<br>
          <strong>Impact:</strong> Unauthorized access to ${exposed ? exposed.toLocaleString() : "247"} customer records confirmed.<br>
          <strong>Data involved:</strong> names, email addresses, password hashes.<br>
          <strong>External exfiltration:</strong> Not established.<br>
          <strong>Containment:</strong> Vulnerable functionality restricted and malicious traffic blocked.<br>
          <strong>Remediation:</strong> Parameterized database query implemented through PATCH-204.<br>
          <strong>Security validation:</strong> ${state.patchTested ? "3/3 tests passed; exploit no longer reproducible." : "Pending AppSec validation."}<br>
          <strong>Legal assessment:</strong> ${state.legalDecisionRecorded ? "Completed." : "Pending."}<br>
          <strong>Residual risk:</strong> ${state.patchDeployed && state.legalDecisionRecorded ? "VERY LOW" : state.patchTested ? "LOW" : "MEDIUM"}</p>
        </div>
        <div class="card lessons">
          <h3>Incident Clock</h3>
          <div class="readiness-list">
            <div class="ready-row ${state.incidentClock.detectedAt !== null ? "done" : ""}"><span>${state.incidentClock.detectedAt !== null ? "✓" : "?"}</span><span><strong>Detected at:</strong> ${state.incidentClock.detectedAt === null ? "Not recorded" : incidentTime(state.incidentClock.detectedAt)}</span></div>
            <div class="ready-row ${state.incidentClock.acknowledgedAt !== null ? "done" : ""}"><span>${state.incidentClock.acknowledgedAt !== null ? "✓" : "?"}</span><span><strong>Acknowledged at:</strong> ${state.incidentClock.acknowledgedAt === null ? "Not recorded" : incidentTime(state.incidentClock.acknowledgedAt)}</span></div>
            <div class="ready-row ${state.incidentClock.escalatedAt !== null ? "done" : ""}"><span>${state.incidentClock.escalatedAt !== null ? "✓" : "?"}</span><span><strong>Escalated at:</strong> ${state.incidentClock.escalatedAt === null ? "Not recorded" : incidentTime(state.incidentClock.escalatedAt)}</span></div>
            <div class="ready-row ${state.incidentClock.containedAt !== null ? "done" : ""}"><span>${state.incidentClock.containedAt !== null ? "✓" : "?"}</span><span><strong>Contained at:</strong> ${state.incidentClock.containedAt === null ? "Not recorded" : incidentTime(state.incidentClock.containedAt)}</span></div>
            <div class="ready-row ${state.incidentClock.recoveredAt !== null ? "done" : ""}"><span>${state.incidentClock.recoveredAt !== null ? "✓" : "?"}</span><span><strong>Recovered at:</strong> ${state.incidentClock.recoveredAt === null ? "Not recorded" : incidentTime(state.incidentClock.recoveredAt)}</span></div>
            <div class="ready-row ${state.incidentClock.closedAt !== null ? "done" : ""}"><span>${state.incidentClock.closedAt !== null ? "✓" : "?"}</span><span><strong>Closed at:</strong> ${state.incidentClock.closedAt === null ? "Not recorded" : incidentTime(state.incidentClock.closedAt)}</span></div>
          </div>
        </div>
        <div class="card lessons">
          <h3>Post-Incident Review</h3>
          <p><strong>Root cause:</strong> Dynamic SQL construction in customer lookup.</p>
          <p><strong>Control gaps:</strong> Missing parameterized query enforcement, insufficient SQLi regression coverage, and delayed evidence-to-commander handoff.</p>
          <p><strong>Follow-up owners:</strong> AppSec owns secure query pattern checks; SOC owns SQLi escalation runbook; Commander owns decision log review; Legal owns notification rationale archive.</p>
          <p><strong>Remediation deadlines:</strong> regression rule in 7 days, secure coding check in 14 days, tabletop replay in 30 days.</p>
        </div>
        <div class="card lessons">
          <h3>End-to-End Incident Journey</h3>
          <p><strong>Cross-role completion:</strong> ${journeyComplete}%</p>
          <div class="readiness-list">${journey.map(item => `<div class="ready-row ${item[1] ? "done" : ""}"><span>${item[1] ? "✓" : "?"}</span><span><strong>${item[0]}:</strong> ${item[2]}</span></div>`).join("")}</div>
        </div>
        <div class="card lessons">
          <h3>What you did well</h3>
          <p><strong>What you did well:</strong> ${didWell.length ? didWell.join(", ") : "The incident needs stronger response actions before closure."}</p>
        </div>
        <div class="card lessons">
          <h3>What increased the impact</h3>
          <p>${riskRaised.length ? riskRaised.join("; ") : "No major risk-increasing decisions recorded."}</p>
          <p><strong>Missed evidence:</strong> ${missedEvidence.length ? missedEvidence.join(", ") : "No critical evidence missed."}</p>
          <p><strong>Weak areas:</strong> ${missed.length ? missed.join(", ") : "No major weak competency in this run."}</p>
        </div>
        <div class="card lessons">
          <h3>Recommended Response</h3>
          <p>Assign the WAF alert, pivot on 198.51.100.24, preserve HTTP/WAF/DB evidence, confirm affected tables, request containment with evidence attached, test the parameterized query patch, then close with a timeline and scope-backed report.</p>
          <p><strong>Decisions that reduced risk:</strong> ${riskReduced.length ? riskReduced.join("; ") : "No strong risk-reducing decisions recorded."}</p>
          <p><strong>Attacker progression:</strong> ${attackerStory.length ? attackerStory.join(" | ") : "Attacker progression stayed limited during the simulation."}</p>
        </div>
        <div class="card lessons">
          <h3>Your decisions</h3>
          ${decisions.map((item, index) => `<p><strong>${index + 1}. ${item.choice}</strong><br>${item.outcome}</p>`).join("")}
        </div>
        <div class="card lessons">
          <h3>Recommended improvements</h3>
          <p>1. Use parameterized queries and automated SQLi checks.</p>
          <p>2. Treat active exploitation as an incident, not just a bug.</p>
          <p>3. Preserve evidence before changes that alter logs or system state.</p>
          <p>4. Build a runbook connecting CTF findings to SOC, legal, engineering, and business owners.</p>
        </div>
      `;
      els.report.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function restart() {
      const keepLoggedIn = state.loggedIn;
      const currentUser = state.user;
      const currentRole = state.role;
      state.phase = 0;
      state.selected = false;
      state.activeTab = "";
      state.activeEvent = 0;
      state.visualView = "attack";
      state.selectedNode = null;
      state.selectedKillStep = 0;
      state.checks = {};
      state.appliedRecs = {};
      state.loggedIn = keepLoggedIn;
      state.selectedLoginRole = null;
      state.user = keepLoggedIn ? currentUser : null;
      state.role = keepLoggedIn ? currentRole : "SOC Analyst";
      state.answeredMessages = {};
      state.selectedEvidence = {};
      state.collectedEvidence = {};
      state.selectedKillEvent = null;
      state.killAssignments = {};
      state.approvals = [];
      state.inboxStatuses = {};
      state.selectedEvidenceRow = null;
      state.objectiveStep = 0;
      state.reportReadiness = 0;
      state.attackerProgress = 0;
      state.stageIndex = 0;
      state.attackerHold = 0;
      state.paused = false;
      state.demoSpeed = 1;
      state.serviceHealth = 100;
      state.detectedTime = null;
      state.containmentTime = null;
      state.evidenceFilter = "all";
      state.highlightEvidenceId = null;
      state.elapsedSeconds = 0;
      state.recordsExposed = null;
      state.incidentClock = {
        detectedAt: null,
        acknowledgedAt: null,
        escalatedAt: null,
        containedAt: null,
        recoveredAt: null,
        closedAt: null
      };
      state.handoffs = {
        commander: { version: 0, updatedAt: null, summary: "No SOC handoff yet." },
        appsec: { version: 0, updatedAt: null, summary: "No remediation handoff yet." },
        legal: { version: 0, updatedAt: null, summary: "No legal handoff yet." }
      };
      state.handoffViews = { commander: 0, appsec: 0, legal: 0 };
      state.injectsSeen = {};
      state.supportComplaints = 0;
      state.monitoringStableSince = null;
      state.recoveryAuthorized = false;
      state.terminalLines = ["SOC TERMINAL READY", "type 'help' to list commands"];
      state.liveTick = 0;
      state.patchTested = false;
      state.patchDeployed = false;
      state.legalAnswer = "";
      state.selectedInbox = "";
      state.wafAlertOpened = false;
      state.score = 0;
      state.risk = 44;
      state.evidence = 0;
      state.loss = 0;
      state.history = [];
      state.actionTimeline = [
        { time: "09:12", actor: "System", action: "WAF alert received for customer-portal-prod" }
      ];
      state.evidenceNotes = {};
      state.commanderAccepted = false;
      state.commandDecision = null;
      state.commandComms = {};
      state.commanderSlaBreached = false;
      state.appsecHandoffAccepted = false;
      state.appsecBaselineRun = false;
      state.appsecExploitReproduced = false;
      state.appsecTraceInspected = false;
      state.appsecRootCauseConfirmed = false;
      state.appsecSelectedPatch = "parameterized";
      state.appsecPatchApplied = false;
      state.appsecDeploymentRequested = false;
      state.legalHandoffAccepted = false;
      state.legalDataClasses = {};
      state.legalExposureSaved = false;
      state.legalBreachStatus = "PENDING";
      state.legalRiskLevel = "PENDING";
      state.legalAuthorityNotification = "PENDING";
      state.legalSubjectNotification = "PENDING";
      state.legalRationale = "";
      state.legalDecisionRecorded = false;
      state.legalClockStartedAt = null;
      state.legalComms = {};
      if (els.pauseSimulationBtn) els.pauseSimulationBtn.textContent = "Pause simulation";
      if (els.demoSpeedSelect) els.demoSpeedSelect.value = "1";
      els.report.className = "panel report";
      els.report.innerHTML = "";
      renderPhase();
      renderLogin();
      renderRoles();
      renderComms();
      renderReportBuilder();
      showPage(keepLoggedIn ? "warroom" : "roles");
    }

    const canvas = $("attackMap");
    const ctx = canvas.getContext("2d");
    const killLabCanvas = $("killLabCanvas");
    const killLabCtx = killLabCanvas.getContext("2d");
    const radarCanvas = $("riskRadar");
    const radarCtx = radarCanvas.getContext("2d");
    const nodes = [
      { id: "attacker", label: "Attacker", x: .12, y: .34, color: "#ff6673" },
      { id: "waf", label: "WAF", x: .35, y: .34, color: "#ffd166" },
      { id: "app", label: "Web App", x: .57, y: .34, color: "#53a7ff" },
      { id: "db", label: "Database", x: .80, y: .34, color: "#a78bfa" },
      { id: "soc", label: "SOC", x: .43, y: .72, color: "#54e0ff" },
      { id: "legal", label: "Legal", x: .66, y: .72, color: "#62df91" }
    ];

    const links = [
      ["attacker", "waf"], ["waf", "app"], ["app", "db"], ["waf", "soc"], ["db", "soc"], ["soc", "legal"]
    ];

    function discoveredNodeIds() {
      const ids = new Set(["attacker", "app"]);
      if (state.collectedEvidence["E-004"] || state.evidence >= 18) ids.add("waf");
      if (state.collectedEvidence["E-005"] || state.evidence >= 35) ids.add("db");
      if (state.collectedEvidence["E-006"] || state.attackerProgress >= 62) ids.add("soc");
      if (state.evidence >= 55 || state.role === "Legal/Compliance") ids.add("legal");
      return ids;
    }

    let lastNodePositions = {};
    let lastKillPositions = [];

    function drawRoundedRect(x, y, width, height, radius) {
      ctx.beginPath();
      ctx.moveTo(x + radius, y);
      ctx.arcTo(x + width, y, x + width, y + height, radius);
      ctx.arcTo(x + width, y + height, x, y + height, radius);
      ctx.arcTo(x, y + height, x, y, radius);
      ctx.arcTo(x, y, x + width, y, radius);
      ctx.closePath();
    }

    function drawKillChainOn(context, targetCanvas, time, trackPositions) {
      const rect = targetCanvas.getBoundingClientRect();
      const stages = ["Recon", "Exploit", "Enumerate", "Contain", "Recover"];
      const active = Math.min(stages.length - 1, state.phase + (state.risk > 60 ? 1 : 0));
      const startX = 38;
      const step = (rect.width - 76) / (stages.length - 1);
      const y = rect.height * .48;
      trackPositions.length = 0;
      stages.forEach((stage, index) => {
        const x = startX + step * index;
        trackPositions.push({ index, x, y, label: stage });
        if (index > 0) {
          context.beginPath();
          context.moveTo(startX + step * (index - 1), y);
          context.lineTo(x, y);
          context.strokeStyle = index <= active ? "rgba(84,224,255,.75)" : "rgba(148,163,184,.28)";
          context.lineWidth = 2;
          context.stroke();
        }
        const selected = state.selectedKillStep === index;
        context.beginPath();
        context.arc(x, y, selected ? 23 : index <= active ? 18 : 14, 0, Math.PI * 2);
        context.fillStyle = selected ? "rgba(98,223,145,.18)" : index <= active ? "rgba(84,224,255,.16)" : "rgba(5,9,16,.95)";
        context.strokeStyle = selected ? "#62df91" : index <= active ? "#54e0ff" : "rgba(148,163,184,.38)";
        context.lineWidth = 2;
        context.fill();
        context.stroke();
        if (index === active || selected) {
          context.beginPath();
          context.arc(x, y, 25 + Math.sin(time / 260) * 4, 0, Math.PI * 2);
          context.strokeStyle = selected ? "rgba(98,223,145,.24)" : "rgba(84,224,255,.18)";
          context.stroke();
        }
        context.fillStyle = "rgba(237,245,255,.92)";
        context.font = "12px system-ui, sans-serif";
        context.textAlign = "center";
        context.fillText(stage, x, y + 42);
      });
    }

    function drawKillChain(rect, time) {
      drawKillChainOn(ctx, canvas, time, lastKillPositions);
    }

    let lastKillLabPositions = [];

    function isCanvasVisible(targetCanvas) {
      if (!targetCanvas || document.visibilityState === "hidden") return false;
      const rect = targetCanvas.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    }

    function scheduleCanvasFrame(drawer, isVisible) {
      if (isVisible) {
        requestAnimationFrame(drawer);
        return;
      }
      window.setTimeout(() => requestAnimationFrame(drawer), 300);
    }

    function drawKillLab(time) {
      if (!isCanvasVisible(killLabCanvas)) {
        scheduleCanvasFrame(drawKillLab, false);
        return;
      }
      const rect = killLabCanvas.getBoundingClientRect();
      const scale = window.devicePixelRatio || 1;
      const width = Math.max(1, Math.floor(rect.width * scale));
      const height = Math.max(1, Math.floor(rect.height * scale));
      if (killLabCanvas.width !== width || killLabCanvas.height !== height) {
        killLabCanvas.width = width;
        killLabCanvas.height = height;
      }
      killLabCtx.setTransform(scale, 0, 0, scale, 0, 0);
      killLabCtx.clearRect(0, 0, rect.width, rect.height);
      drawKillChainOn(killLabCtx, killLabCanvas, time, lastKillLabPositions);
      scheduleCanvasFrame(drawKillLab, true);
    }

    function prepareCanvas(targetCanvas, context) {
      const rect = targetCanvas.getBoundingClientRect();
      const scale = window.devicePixelRatio || 1;
      const width = Math.max(1, Math.floor(rect.width * scale));
      const height = Math.max(1, Math.floor(rect.height * scale));
      if (targetCanvas.width !== width || targetCanvas.height !== height) {
        targetCanvas.width = width;
        targetCanvas.height = height;
      }
      context.setTransform(scale, 0, 0, scale, 0, 0);
      context.clearRect(0, 0, rect.width, rect.height);
      return rect;
    }

    function renderRealScene() {
      const phase = state.selectedKillStep;
      const scenes = [
        `<div class="split-scene">
          <div class="scene-window"><div class="window-bar"><span class="window-dots"><span></span><span></span><span></span></span><span>Burp / Proxy history</span></div><div class="scene-body">
            <div class="scene-line"><span class="ts">09:04</span><span>GET /customers?id=12 <span class="good">200</span></span></div>
            <div class="scene-line"><span class="ts">09:05</span><span>GET /admin/export <span class="warn">403</span></span></div>
            <div class="scene-line"><span class="ts">09:06</span><span>GET /customers?id=12' <span class="bad">500 SQL error</span></span></div>
            <div class="scene-line"><span class="ts">09:07</span><span>parameter id appears injectable</span></div>
          </div></div>
          <div class="scene-window"><div class="window-bar"><span class="live-badge">LIVE RECON</span><span>route discovery</span></div><div class="scene-body">
            <div class="request-card"><b>Observed pattern</b><span>same source probes id, export, profile, and admin paths</span></div>
            <div class="request-card"><b>Defender view</b><span>low-noise recon can look like normal browsing unless correlated</span></div>
          </div></div>
        </div>`,
        `<div class="scene-window"><div class="window-bar"><span class="window-dots"><span></span><span></span><span></span></span><span>Live exploit trace</span></div><div class="scene-body">
          <div class="scene-line"><span class="ts">REQ</span><span>GET /customers?id=12 UNION SELECT email,password_hash FROM users--</span></div>
          <div class="scene-line"><span class="ts">WAF</span><span class="bad">SQLi signature matched: UNION SELECT</span></div>
          <div class="scene-line"><span class="ts">APP</span><span class="warn">query built from user input</span></div>
          <div class="scene-line"><span class="ts">DB</span><span class="bad">247 customer records accessed; external exfiltration not established</span></div>
          <div class="scene-line"><span class="ts">CTF</span><span class="good">flag found</span></div>
          <div class="scene-line"><span class="ts">REAL</span><span class="warn">possible customer data exposure; legal review needed</span></div>
        </div></div>`,
        `<div class="scene-window"><div class="window-bar"><span class="live-badge">DB AUDIT STREAM</span><span>table enumeration</span></div><div class="scene-body fake-table">
          <div class="fake-row hot"><span>users</span><span>email,password_hash</span><span>48k</span></div>
          <div class="fake-row hot"><span>customers</span><span>phone,plan,address</span><span>31k</span></div>
          <div class="fake-row"><span>orders</span><span>order_id,total</span><span>12k</span></div>
          <div class="fake-row"><span>tokens</span><span>reset_token,expires</span><span>840</span></div>
          <div class="scene-line"><span class="ts">SIEM</span><span class="warn">same IP touched admin export before SQLi</span></div>
        </div></div>`,
        `<div class="split-scene">
          <div class="scene-window"><div class="window-bar"><span class="live-badge">CONTAINMENT CONSOLE</span><span>controls</span></div><div class="scene-body control-stack">
            <div class="control-item"><span>WAF SQLi rule /customers</span><span class="toggle-on">BLOCK</span></div>
            <div class="control-item"><span>web_portal_ro credential</span><span class="toggle-on">ROTATED</span></div>
            <div class="control-item"><span>Parameterized query patch</span><span class="toggle-on">DEPLOYING</span></div>
            <div class="control-item"><span>Error-rate monitor</span><span class="toggle-on">WATCHING</span></div>
          </div></div>
          <div class="scene-window"><div class="window-bar"><span class="window-dots"><span></span><span></span><span></span></span><span>traffic after block</span></div><div class="scene-body">
            <div class="scene-line"><span class="ts">09:47</span><span class="bad">payload blocked at edge</span></div>
            <div class="scene-line"><span class="ts">09:49</span><span class="good">normal portal traffic healthy</span></div>
            <div class="scene-line"><span class="ts">09:52</span><span class="good">no SQLi passed to app</span></div>
          </div></div>
        </div>`,
        `<div class="doc-stack">
          <div class="doc-card"><b>Clean state</b><span>No new SQLi reached the app after WAF block and patch deployment.</span></div>
          <div class="doc-card"><b>Scope report</b><span>Confirmed table scans; payment data not stored in affected DB.</span></div>
          <div class="doc-card"><b>Legal review</b><span>Facts, likely exposure, unknowns, and notification timeline prepared.</span></div>
          <div class="doc-card"><b>Runbook</b><span>Web exploit response playbook created for SOC, AppSec, Legal, Engineering.</span></div>
          <div class="doc-card"><b>Prevention</b><span>SAST rule, parameterized query standard, and credential rotation added.</span></div>
          <div class="doc-card"><b>Executive brief</b><span>Business impact, containment status, and lessons learned summarized.</span></div>
        </div>`
      ];
      if (els.phaseRealScene) els.phaseRealScene.innerHTML = scenes[phase] || scenes[0];
    }

    function renderKillchainDetail() {
      const detail = killChainDetails[state.selectedKillStep] || killChainDetails[0];
      els.killchainDetail.innerHTML = `<strong>${detail[0]}</strong><p class="small">${detail[1]}</p>`;
    }

    function drawDataExposure(rect) {
      const rows = [
        ["Emails", 78],
        ["Phones", 64],
        ["Hashes", 52],
        ["Payment", 8],
        ["Sessions", Math.max(12, state.risk - 25)]
      ];
      const x = 42;
      let y = 82;
      ctx.font = "12px system-ui, sans-serif";
      rows.forEach(row => {
        ctx.fillStyle = "rgba(237,245,255,.9)";
        ctx.textAlign = "left";
        ctx.fillText(row[0], x, y);
        const barX = x + 88;
        const barW = Math.max(80, rect.width - barX - 58);
        drawRoundedRect(barX, y - 10, barW, 10, 6);
        ctx.fillStyle = "rgba(148,163,184,.18)";
        ctx.fill();
        drawRoundedRect(barX, y - 10, barW * row[1] / 100, 10, 6);
        ctx.fillStyle = row[1] > 65 ? "rgba(255,102,115,.86)" : row[1] > 35 ? "rgba(255,209,102,.86)" : "rgba(98,223,145,.86)";
        ctx.fill();
        ctx.fillStyle = "rgba(159,176,198,.95)";
        ctx.textAlign = "right";
        ctx.fillText(`${row[1]}%`, rect.width - 28, y);
        y += 34;
      });
    }

    function drawRiskRadar(time) {
      if (!isCanvasVisible(radarCanvas)) {
        scheduleCanvasFrame(drawRiskRadar, false);
        return;
      }
      const rect = radarCanvas.getBoundingClientRect();
      const scale = window.devicePixelRatio || 1;
      const width = Math.max(1, Math.floor(rect.width * scale));
      const height = Math.max(1, Math.floor(rect.height * scale));
      if (radarCanvas.width !== width || radarCanvas.height !== height) {
        radarCanvas.width = width;
        radarCanvas.height = height;
      }
      radarCtx.setTransform(scale, 0, 0, scale, 0, 0);
      radarCtx.clearRect(0, 0, rect.width, rect.height);
      const cx = rect.width / 2;
      const cy = rect.height / 2 + 8;
      const radius = Math.min(rect.width, rect.height) * .32;
      const values = state.role === "Legal/Compliance" ? [
        ["Exposure", state.legalExposureSaved ? 72 : 38],
        ["Evidence", state.legalDecisionRecorded ? 86 : state.legalExposureSaved ? 65 : 28],
        ["Notification", state.legalAuthorityNotification === "REQUIRED" ? 82 : 35],
        ["Customer Risk", state.legalRiskLevel === "HIGH" ? 78 : 42],
        ["Legal Risk", state.legalDecisionRecorded ? 34 : 68]
      ] : [
        ["Exploit", state.risk],
        ["Data", clamp(40 + state.risk * .4 - state.evidence * .2, 0, 100)],
        ["Evidence", state.evidence],
        ["Business", clamp(state.loss / 7000, 0, 100)],
        ["Recovery", clamp(80 - state.risk + state.score * .25, 0, 100)]
      ];
      for (let ring = 1; ring <= 4; ring += 1) {
        radarCtx.beginPath();
        values.forEach((_, index) => {
          const angle = -Math.PI / 2 + index * Math.PI * 2 / values.length;
          const x = cx + Math.cos(angle) * radius * ring / 4;
          const y = cy + Math.sin(angle) * radius * ring / 4;
          if (index === 0) radarCtx.moveTo(x, y);
          else radarCtx.lineTo(x, y);
        });
        radarCtx.closePath();
        radarCtx.strokeStyle = "rgba(148,163,184,.2)";
        radarCtx.stroke();
      }
      const pulse = 1 + Math.sin(time / 500) * .025;
      radarCtx.beginPath();
      values.forEach((item, index) => {
        const angle = -Math.PI / 2 + index * Math.PI * 2 / values.length;
        const r = radius * item[1] / 100 * pulse;
        const x = cx + Math.cos(angle) * r;
        const y = cy + Math.sin(angle) * r;
        if (index === 0) radarCtx.moveTo(x, y);
        else radarCtx.lineTo(x, y);
      });
      radarCtx.closePath();
      radarCtx.fillStyle = "rgba(84,224,255,.18)";
      radarCtx.strokeStyle = "rgba(84,224,255,.85)";
      radarCtx.lineWidth = 2;
      radarCtx.fill();
      radarCtx.stroke();
      values.forEach((item, index) => {
        const angle = -Math.PI / 2 + index * Math.PI * 2 / values.length;
        const x = cx + Math.cos(angle) * (radius + 26);
        const y = cy + Math.sin(angle) * (radius + 26);
        radarCtx.fillStyle = "rgba(237,245,255,.92)";
        radarCtx.font = "12px system-ui, sans-serif";
        radarCtx.textAlign = "center";
        radarCtx.fillText(item[0], x, y);
        const px = cx + Math.cos(angle) * radius * item[1] / 100;
        const py = cy + Math.sin(angle) * radius * item[1] / 100;
        radarCtx.beginPath();
        radarCtx.arc(px, py, 3.5, 0, Math.PI * 2);
        radarCtx.fillStyle = item[0] === "Evidence" ? "rgba(98,223,145,.95)" : "rgba(255,209,102,.95)";
        radarCtx.fill();
      });
      scheduleCanvasFrame(drawRiskRadar, true);
    }

    function drawMap(time) {
      if (!isCanvasVisible(canvas)) {
        scheduleCanvasFrame(drawMap, false);
        return;
      }
      const rect = canvas.getBoundingClientRect();
      const scale = window.devicePixelRatio || 1;
      const width = Math.max(1, Math.floor(rect.width * scale));
      const height = Math.max(1, Math.floor(rect.height * scale));
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }
      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      ctx.clearRect(0, 0, rect.width, rect.height);

      if (state.visualView === "killchain") {
        drawKillChain(rect, time);
        scheduleCanvasFrame(drawMap, true);
        return;
      }

      if (state.visualView === "data") {
        drawDataExposure(rect);
        scheduleCanvasFrame(drawMap, true);
        return;
      }

      const discovered = discoveredNodeIds();
      const visibleNodes = nodes.filter(node => discovered.has(node.id));
      const byId = Object.fromEntries(nodes.map(node => [node.id, { ...node, px: node.x * rect.width, py: node.y * rect.height }]));
      lastNodePositions = byId;

      links.forEach(link => {
        if (!discovered.has(link[0]) || !discovered.has(link[1])) return;
        const a = byId[link[0]];
        const b = byId[link[1]];
        ctx.beginPath();
        ctx.moveTo(a.px, a.py);
        ctx.lineTo(b.px, b.py);
        ctx.strokeStyle = "rgba(148,163,184,.32)";
        ctx.lineWidth = 1;
        ctx.stroke();
      });

      const packetLinks = (state.phase < 2 ? links.slice(0, 3) : state.phase === 2 ? links.slice(0, 5) : links).filter(link => discovered.has(link[0]) && discovered.has(link[1]));
      packetLinks.forEach((link, index) => {
        const a = byId[link[0]];
        const b = byId[link[1]];
        const speed = state.risk > 60 ? 850 : 1300;
        const t = ((time + index * 240) % speed) / speed;
        const px = a.px + (b.px - a.px) * t;
        const py = a.py + (b.py - a.py) * t;
        ctx.beginPath();
        ctx.arc(px, py, 4.2, 0, Math.PI * 2);
        ctx.fillStyle = link[0] === "attacker" ? "rgba(255,102,115,.95)" : "rgba(84,224,255,.9)";
        ctx.shadowColor = ctx.fillStyle;
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      nodes.forEach(node => {
        const n = byId[node.id];
        if (!discovered.has(node.id)) {
          ctx.beginPath();
          ctx.arc(n.px, n.py, 16, 0, Math.PI * 2);
          ctx.fillStyle = "rgba(5,9,16,.75)";
          ctx.strokeStyle = "rgba(148,163,184,.22)";
          ctx.fill();
          ctx.stroke();
          ctx.fillStyle = "rgba(159,176,198,.75)";
          ctx.font = "12px system-ui, sans-serif";
          ctx.textAlign = "center";
          ctx.fillText("?", n.px, n.py + 4);
          return;
        }
        const pulse = 1 + Math.sin(time / 420 + n.x * 8) * 0.07;
        ctx.beginPath();
        ctx.arc(n.px, n.py, 18 * pulse, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(5,9,16,.95)";
        ctx.strokeStyle = node.color;
        ctx.lineWidth = 2;
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(n.px, n.py, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.fill();
        ctx.font = "12px system-ui, sans-serif";
        ctx.fillStyle = "rgba(237,245,255,.92)";
        ctx.textAlign = "center";
        ctx.fillText(node.label, n.px, n.py + 36);
      });

      scheduleCanvasFrame(drawMap, true);
    }

    function renderViewButtons() {
      els.viewButtons.querySelectorAll("button").forEach(button => {
        button.classList.toggle("active", button.dataset.view === state.visualView);
      });
      const mainMap = document.querySelector(".center .map-panel");
      if (mainMap) mainMap.dataset.view = state.visualView;
      const labels = {
        attack: current().map,
        killchain: "See where the incident is in the attacker lifecycle.",
        data: "Estimate which data classes are exposed or protected."
      };
      els.mapCaption.textContent = labels[state.visualView];
    }

    function renderNodeInspector() {
      if (!state.selectedNode || !nodeInfo[state.selectedNode]) {
        els.nodeInspector.innerHTML = "<strong>Click a system node</strong><p class=\"small\">Inspect attacker, WAF, app, database, SOC, or legal/compliance role.</p>";
        return;
      }
      const [title, text] = nodeInfo[state.selectedNode];
      els.nodeInspector.innerHTML = `<strong>${title}</strong><p class="small">${text}</p>`;
    }

    els.viewButtons.querySelectorAll("button").forEach(button => {
      button.addEventListener("click", () => {
        state.visualView = button.dataset.view;
        renderViewButtons();
      });
    });

    canvas.addEventListener("click", event => {
      if (state.visualView !== "attack") return;
      const rect = canvas.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const hit = Object.values(lastNodePositions).find(node => Math.hypot(node.px - x, node.py - y) < 28);
      if (hit) {
        state.selectedNode = hit.id;
        renderNodeInspector();
      }
    });

    canvas.addEventListener("click", event => {
      if (state.visualView !== "killchain") return;
      const rect = canvas.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const hit = lastKillPositions.find(item => Math.hypot(item.x - x, item.y - y) < 34);
      if (hit) {
        state.selectedKillStep = hit.index;
        renderKillchainDetail();
        renderKillLab();
      }
    });

    killLabCanvas.addEventListener("click", event => {
      const rect = killLabCanvas.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const hit = lastKillLabPositions.find(item => Math.hypot(item.x - x, item.y - y) < 34);
      if (hit) {
        state.selectedKillStep = hit.index;
        renderKillchainDetail();
        renderKillLab();
      }
    });

    document.querySelectorAll(".nav-btn").forEach(button => {
      button.addEventListener("click", () => showPage(button.dataset.page));
    });
    document.querySelectorAll("[data-page-shortcut]").forEach(button => {
      button.addEventListener("click", () => showPage(button.dataset.pageShortcut));
    });

    if (els.eventDrawer) {
      els.eventDrawer.addEventListener("click", event => {
        if (event.target === els.eventDrawer) closeDrawer();
      });
      document.addEventListener("keydown", event => {
        if (event.key === "Escape" && els.eventDrawer.classList.contains("open")) closeDrawer();
      });
    }

    els.next.addEventListener("click", next);
    els.finish.addEventListener("click", showReport);
    els.restart.addEventListener("click", restart);
    els.generateReportBtn.addEventListener("click", generateRoleReport);
    els.closeIncidentBtn.addEventListener("click", () => {
      const requiredReadiness = state.role === "Legal/Compliance" ? 85 : 80;
      const blocking = closureBlockers();
      if (blocking.length) {
        toast("Final closure locked", `Complete first: ${blocking.join(", ")}.`, "bad");
        return;
      }
      if (state.reportReadiness < requiredReadiness) {
        toast("Close blocked", `Report readiness must reach ${requiredReadiness}% before closure.`, "bad");
        return;
      }
      if (state.incidentClock.closedAt === null) state.incidentClock.closedAt = state.elapsedSeconds;
      showReport();
    });
    els.ctfToggle.addEventListener("click", () => {
      els.flagTerminal.classList.toggle("ctf-hidden");
      els.ctfToggle.textContent = els.flagTerminal.classList.contains("ctf-hidden") ? "View original CTF evidence" : "Hide original CTF evidence";
    });
    els.promptRow.querySelectorAll("button").forEach(button => {
      button.addEventListener("click", () => renderAI(button.dataset.prompt));
    });
    if (els.acceptAppsecHandoffBtn) els.acceptAppsecHandoffBtn.addEventListener("click", () => {
      if (!appsecReady()) {
        toast("AppSec handoff locked", "Commander must assign remediation before AppSec can accept.", "bad");
        return;
      }
      markHandoffViewed("appsec");
      state.appsecHandoffAccepted = true;
      state.score += 5;
      logAction("AppSec accepted SOC handoff for /customers SQLi", state.user ? state.user.name : "AppSec Engineer");
      toast("Handoff accepted", "AppSec owns reproduction, root cause, patch, and validation.");
      if (els.eventDrawer) els.eventDrawer.classList.remove("open");
      renderAppSec();
      renderPhases();
      renderObjective();
    });
    if (els.runBaselineBtn) els.runBaselineBtn.addEventListener("click", () => {
      state.appsecBaselineRun = true;
      logAction("AppSec ran baseline request for /customers?id=12");
      toast("Baseline captured", "Normal response size and behavior recorded.");
      renderAppSec();
    });
    if (els.runExploitBtn) els.runExploitBtn.addEventListener("click", () => {
      if (!state.appsecBaselineRun) state.appsecBaselineRun = true;
      state.appsecExploitReproduced = true;
      state.evidence = clamp(state.evidence + 12, 0, 100);
      state.score += 8;
      state.attackerHold = Math.max(state.attackerHold, 25);
      logAction("AppSec safely reproduced SQL injection in lab");
      toast("Exploit reproduced", "Response delta and DB anomaly confirm exploitability.");
      renderAppSec();
      renderMetrics();
      renderPhases();
      renderReportBuilder();
    });
    els.inspectCodeBtn.addEventListener("click", () => {
      state.appsecTraceInspected = true;
      openDrawer("Code Trace", `<div class="code-window">req.query.id
  ↓
query string concatenation
  ↓
db.query(query)

Finding: user-controlled input reaches SQL execution without parameterization.</div>`);
      state.score += 4;
      logAction("AppSec inspected vulnerable query construction");
      renderAppSec();
      renderPhases();
    });
    if (els.confirmRootCauseBtn) els.confirmRootCauseBtn.addEventListener("click", () => {
      if (!state.appsecTraceInspected) {
        toast("Trace required", "Inspect data flow before confirming root cause.", "bad");
        return;
      }
      state.appsecRootCauseConfirmed = true;
      state.score += 8;
      state.evidence = clamp(state.evidence + 8, 0, 100);
      logAction("AppSec confirmed root cause: dynamic SQL construction");
      toast("Root cause confirmed", "Dynamic SQL construction is the remediation target.");
      renderAppSec();
      renderMetrics();
      renderPhases();
      renderReportBuilder();
    });
    if (els.applyPatchBtn) els.applyPatchBtn.addEventListener("click", () => {
      if (!state.appsecRootCauseConfirmed) {
        toast("Patch blocked", "Confirm the root cause before applying a fix.", "bad");
        return;
      }
      if (state.appsecSelectedPatch !== "parameterized") {
        state.risk = clamp(state.risk + 4, 0, 100);
        toast("Compensating control only", "This does not remove the root cause. Choose parameterized query.", "bad");
        logAction(`AppSec rejected weak remediation option: ${state.appsecSelectedPatch}`);
        renderMetrics();
        return;
      }
      state.appsecPatchApplied = true;
      state.score += 10;
      state.risk = clamp(state.risk - 8, 0, 100);
      logAction("AppSec created PATCH-204 with parameterized query");
      toast("Patch created", "Parameterized query removes the SQL injection root cause.");
      renderAppSec();
      renderMetrics();
      renderPhases();
      renderReportBuilder();
    });
    els.testPatchBtn.addEventListener("click", () => {
      if (!state.appsecPatchApplied) {
        toast("Tests blocked", "Apply the parameterized query patch first.", "bad");
        return;
      }
      state.patchTested = true;
      state.evidence = clamp(state.evidence + 5, 0, 100);
      state.score += 8;
      logAction("AppSec ran security regression tests: 3/3 passed");
      toast("Regression passed", "Normal lookup, invalid ID, and SQLi payload tests passed.");
      renderAppSec();
      renderMetrics();
      renderPhases();
      renderReportBuilder();
    });
    els.deployPatchBtn.addEventListener("click", () => {
      if (!state.patchTested) {
        openDrawer("Deployment blocked", `<p class="small">Patch must pass security regression testing before AppSec can request production deployment.</p>`);
        return;
      }
      state.appsecDeploymentRequested = true;
      updateHandoff("commander", "AppSec requests deployment approval: PATCH-204, 3/3 tests passed, rollback ready.");
      if (!state.approvals.some(item => item.type === "PATCH-204 Production Deployment")) {
        state.approvals.push({ id: `APR-${String(42 + state.approvals.length).padStart(4, "0")}`, type: "PATCH-204 Production Deployment", status: "pending", elapsed: 0, needsInfo: false, requester: state.user ? state.user.name : "AppSec Engineer", owner: "Incident Commander", evidenceAttached: true, evidenceAtRequest: state.evidence, reason: "Parameterized query patch passed AppSec regression tests for /customers.", impact: "Low disruption deployment; monitor customer lookup and error rate for 15 minutes." });
      }
      logAction("AppSec requested production deployment approval for PATCH-204");
      toast("Deployment requested", "Incident Commander approval queue received PATCH-204.");
      renderAppSec();
      renderMetrics();
      renderApprovals();
      renderPhases();
      renderReportBuilder();
    });
    document.querySelectorAll("[data-legal-answer]").forEach(button => button.addEventListener("click", () => {
      const answer = button.dataset.legalAnswer;
      state.legalAnswer = answer;
      if (answer === "correct") {
        els.legalDecision.textContent = "Correct: insufficient evidence to declare a reportable breach; investigation ongoing.";
        state.score += 10;
      } else {
        els.legalDecision.textContent = "Risky communication: statement is not supported by current evidence.";
        state.risk = clamp(state.risk + 6, 0, 100);
      }
      renderMetrics();
      renderLegal();
    }));
    if (els.acceptLegalHandoffBtn) els.acceptLegalHandoffBtn.addEventListener("click", () => {
      if (state.legalHandoffAccepted) return;
      if (!legalReady()) {
        toast("Legal handoff locked", "Legal needs confirmed SOC facts and command context first.", "bad");
        return;
      }
      markHandoffViewed("legal");
      state.legalHandoffAccepted = true;
      state.score += 5;
      logAction("Legal accepted incident handoff", "Legal/Compliance");
      toast("Legal handoff accepted", "Compliance workflow opened for data exposure and notification assessment.");
      if (els.eventDrawer) els.eventDrawer.classList.remove("open");
      renderLegal();
      renderObjective();
      renderPhases();
    });
    if (els.saveExposureBtn) els.saveExposureBtn.addEventListener("click", () => {
      if (Object.keys(state.legalDataClasses).filter(key => state.legalDataClasses[key]).length < 2) {
        toast("Assessment incomplete", "Classify at least two data categories before saving exposure.", "bad");
        return;
      }
      state.legalExposureSaved = true;
      state.legalRiskLevel = "MODERATE";
      if (state.recordsExposed === null) state.recordsExposed = 247;
      state.score += 8;
      state.evidence = clamp(state.evidence + 6, 0, 100);
      logAction("Legal saved exposure assessment", "Legal/Compliance");
      toast("Exposure assessment saved", "Evidence sufficiency improved and notification analysis can proceed.");
      renderLegal();
      renderMetrics();
      renderObjective();
      renderPhases();
      renderReportBuilder();
    });
    if (els.recordLegalDecisionBtn) els.recordLegalDecisionBtn.addEventListener("click", () => {
      if (!state.legalExposureSaved) {
        toast("Decision blocked", "Save exposure assessment before recording notification decision.", "bad");
        return;
      }
      const rationale = (els.legalRationale?.value || "").trim();
      if (rationale.length < 20) {
        toast("Rationale required", "Add a short evidence-backed rationale before recording the legal decision.", "bad");
        return;
      }
      state.legalBreachStatus = "CONFIRMED";
      state.legalRiskLevel = "MODERATE";
      state.legalAuthorityNotification = "REQUIRED";
      state.legalSubjectNotification = "PENDING";
      state.legalRationale = rationale;
      state.legalDecisionRecorded = true;
      if (state.legalClockStartedAt === null) state.legalClockStartedAt = state.elapsedSeconds;
      state.score += 12;
      logAction("Legal recorded notification decision and rationale", "Legal/Compliance");
      toast("Legal decision recorded", "Regulatory clock and compliance package updated.");
      if (els.legalDecision) els.legalDecision.textContent = "Decision documented: authority notification required; data-subject communication pending final scope.";
      renderLegal();
      renderMetrics();
      renderObjective();
      renderPhases();
      renderReportBuilder();
    });
    els.requestIsolationBtn.addEventListener("click", () => {
      const hasMinimumContext = state.evidence >= 25 || state.collectedEvidence["E-003"] || state.inboxStatuses.waf === "INVESTIGATING";
      if (!hasMinimumContext) {
        toast("Approval blocked", "Collect or investigate at least one strong signal before requesting portal isolation.", "bad");
        logAction("Portal isolation request blocked: insufficient evidence");
        showPage("evidence");
        state.highlightEvidenceId = "E-003";
        state.selectedEvidenceRow = "E-003";
        renderEvidenceGame();
        return;
      }
      state.approvals.push({ id: `APR-${String(42 + state.approvals.length).padStart(4, "0")}`, type: "Portal Isolation", status: "pending", elapsed: 0, requester: state.user ? state.user.name : state.role, owner: "Incident Commander", evidenceAtRequest: state.evidence, reason: "Block active exploitation path while preserving evidence and minimizing service impact." });
      logAction("Requested portal isolation approval");
      renderApprovals();
    });
    els.requestLegalBtn.addEventListener("click", () => {
      state.approvals.push({ id: `APR-${String(42 + state.approvals.length).padStart(4, "0")}`, type: "Legal Notification Review", status: "pending", elapsed: 0, requester: state.user ? state.user.name : state.role, owner: "Legal/Compliance", evidenceAtRequest: state.evidence, reason: "Determine whether available evidence triggers notification workflow." });
      logAction("Requested legal notification review");
      renderApprovals();
    });
    els.pauseSimulationBtn.addEventListener("click", () => {
      state.paused = !state.paused;
      els.pauseSimulationBtn.textContent = state.paused ? "Resume simulation" : "Pause simulation";
      logAction(state.paused ? "Simulation paused for demo" : "Simulation resumed");
      toast(state.paused ? "Simulation paused" : "Simulation resumed", state.paused ? "Incident clock and attacker movement are stopped." : `Demo speed ${state.demoSpeed}x active.`);
    });
    els.demoSpeedSelect.addEventListener("change", () => {
      state.demoSpeed = Number(els.demoSpeedSelect.value);
      logAction(`Demo speed changed to ${state.demoSpeed}x`);
      toast("Demo speed updated", `Incident pacing is now ${state.demoSpeed}x.`);
    });
    els.contextMenu.querySelectorAll("button").forEach(button => button.addEventListener("click", () => {
      const action = button.dataset.contextAction;
      if (action === "evidence") collectEvidence(state.contextEvidenceId);
      if (action === "ip") runSocCommand("search ip 198.51.100.24");
      if (action === "timeline") runSocCommand("timeline");
      if (action === "escalate") state.approvals.push({ type: "evidence escalation", status: "pending" });
      els.contextMenu.style.display = "none";
      renderApprovals();
    }));
    document.addEventListener("click", event => {
      if (!els.contextMenu.contains(event.target)) els.contextMenu.style.display = "none";
    });

    const interactiveCardSelector = [
      ".landing-card",
      ".card",
      ".command-card",
      ".workspace-card",
      ".role-card",
      ".feed-item",
      ".tradeoff-card",
      ".brief-card",
      ".detail-box",
      ".request-card",
      ".message-card",
      ".doc-card",
      ".demo-account",
      ".confidence-panel",
      ".ai-answer",
      ".radar-wrap",
      ".report-preview",
      ".tool-step",
      ".ready-row",
      ".log-row",
      ".status-light",
      ".heat-row",
      ".inbox-alert",
      ".rec-card",
      ".choice",
      ".outcome",
      ".evidence-pick"
    ].join(", ");

    function bindInteractiveCards(root = document) {
      const cards = [];
      if (root.nodeType === Node.ELEMENT_NODE && root.matches(interactiveCardSelector)) {
        cards.push(root);
      }
      if (root.querySelectorAll) {
        cards.push(...root.querySelectorAll(interactiveCardSelector));
      }
      cards.forEach(card => {
        if (card.dataset.interactiveCardBound === "true") return;
        card.dataset.interactiveCardBound = "true";
        card.classList.add("interactive-card");
        card.style.setProperty("--mouse-x", "50%");
        card.style.setProperty("--mouse-y", "50%");
      });
    }

    let activeInteractiveCard = null;
    let pendingInteractiveMove = null;
    let interactiveMoveFrame = 0;

    function resetActiveInteractiveCard() {
      if (!activeInteractiveCard) return;
      activeInteractiveCard.style.setProperty("--mouse-x", "50%");
      activeInteractiveCard.style.setProperty("--mouse-y", "50%");
      activeInteractiveCard = null;
    }

    function applyInteractiveMove() {
      interactiveMoveFrame = 0;
      if (!pendingInteractiveMove) return;
      const { clientX, clientY, target } = pendingInteractiveMove;
      pendingInteractiveMove = null;
      const card = target instanceof Element ? target.closest(".interactive-card") : null;
      if (!card) {
        resetActiveInteractiveCard();
        return;
      }
      activeInteractiveCard = card;
      const rect = card.getBoundingClientRect();
      card.style.setProperty("--mouse-x", `${clientX - rect.left}px`);
      card.style.setProperty("--mouse-y", `${clientY - rect.top}px`);
    }

    function queueInteractiveMove(event) {
      pendingInteractiveMove = {
        clientX: event.clientX,
        clientY: event.clientY,
        target: event.target
      };
      if (!interactiveMoveFrame) {
        interactiveMoveFrame = requestAnimationFrame(applyInteractiveMove);
      }
    }

    let interactiveCardsInitialized = false;

    function initInteractiveCards() {
      if (interactiveCardsInitialized) return;
      interactiveCardsInitialized = true;
      bindInteractiveCards();
      if (!window.matchMedia("(pointer: coarse)").matches) {
        document.addEventListener("mousemove", queueInteractiveMove, { passive: true });
        document.addEventListener("mouseleave", resetActiveInteractiveCard, { passive: true });
        document.addEventListener("mouseout", event => {
          if (!event.relatedTarget) resetActiveInteractiveCard();
        }, { passive: true });
      }
      const observer = new MutationObserver(mutations => {
        mutations.forEach(mutation => {
          mutation.addedNodes.forEach(node => bindInteractiveCards(node));
        });
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }

    function initLandingMotion() {
      const cards = document.querySelectorAll(".spotlight-card");
      if (!cards.length) return;
      cards.forEach((card, index) => {
        card.classList.add("reveal-ready");
        card.style.setProperty("--reveal-delay", `${index * 110}ms`);
      });
      if (!("IntersectionObserver" in window)) {
        cards.forEach(card => card.classList.add("is-visible"));
        return;
      }
      const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        });
      }, { threshold: 0.28 });
      cards.forEach(card => observer.observe(card));
    }

    restoreSavedSession();
    renderPhase();
    renderLogin();
    renderObjective();
    renderViewButtons();
    renderNodeInspector();
    renderKillchainDetail();
    renderKillLab();
    renderEvidenceTimeline();
    renderRoles();
    renderComms();
    renderReportBuilder();
    renderSocInbox();
    renderKillGame();
    renderAppSec();
    renderLegal();
    renderApprovals();
    renderRecentActions();
    if (state.loggedIn) showPage("warroom");
    initInteractiveCards();
    initLandingMotion();
    requestAnimationFrame(drawMap);
    requestAnimationFrame(drawKillLab);
    requestAnimationFrame(drawRiskRadar);
    window.setInterval(renderLivePulse, 2600);

