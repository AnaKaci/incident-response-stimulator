(function incidentScenarioEngine() {
  const DIFFICULTY_MODES = {
    Beginner: {
      label: "Beginner",
      hints: "direct",
      falsePositiveRate: 0.12,
      logCompleteness: 0.96,
      attackerPressure: 0.65,
      scoreForgiveness: 1.25
    },
    Intermediate: {
      label: "Intermediate",
      hints: "contextual",
      falsePositiveRate: 0.22,
      logCompleteness: 0.88,
      attackerPressure: 1,
      scoreForgiveness: 1
    },
    Advanced: {
      label: "Advanced",
      hints: "minimal",
      falsePositiveRate: 0.34,
      logCompleteness: 0.76,
      attackerPressure: 1.25,
      scoreForgiveness: 0.88
    },
    Expert: {
      label: "Expert",
      hints: "none",
      falsePositiveRate: 0.48,
      logCompleteness: 0.62,
      attackerPressure: 1.55,
      scoreForgiveness: 0.76
    }
  };

  const SCENARIO_FILES = [
    "scenarios/sql-injection.json",
    "scenarios/ransomware.json",
    "scenarios/phishing-account-takeover.json",
    "scenarios/compromised-admin.json",
    "scenarios/cloud-credential-leak.json",
    "scenarios/insider-exfiltration.json",
    "scenarios/webshell-compromise.json",
    "scenarios/supply-chain-compromise.json"
  ];

  const EMBEDDED_SCENARIOS = [
    {
      id: "sql-injection",
      incidentId: "INC-2026-0812",
      title: "SQL Injection Data Exposure",
      description: "Suspicious activity has been detected against the customer portal after SQL injection payloads reached production.",
      difficulty: "Intermediate",
      category: "Web Application Compromise",
      complexity: "4 phase investigation",
      environment: "Customer portal, WAF, web tier, database, IAM, support desk",
      availableRoles: ["SOC Analyst", "Incident Commander", "AppSec Engineer", "Legal/Compliance"],
      referenceImplementation: true,
      seed: "sql-injection-2026-0812",
      initialAlerts: [
        {
          id: "ALERT-WAF-1192",
          source: "WAFLogs",
          title: "Possible SQL injection",
          severity: "HIGH",
          asset: "customer-portal-prod",
          summary: "UNION SELECT pattern against /customers?id= from 198.51.100.24"
        },
        {
          id: "ALERT-DB-8841",
          source: "DatabaseLogs",
          title: "Database read anomaly",
          severity: "HIGH",
          asset: "db-prod-01",
          summary: "web_portal_ro read volume exceeded normal customer lookup baseline"
        }
      ],
      assets: [
        {
          id: "edge-waf-02",
          name: "Edge WAF",
          type: "Security Control",
          criticality: "HIGH",
          operationalStatus: "Healthy",
          securityState: "Suspicious",
          isolation: "Not isolated",
          logging: "Active",
          activeSessions: 0
        },
        {
          id: "customer-portal-prod",
          name: "Customer Portal",
          type: "Web Application",
          criticality: "CRITICAL",
          operationalStatus: "Healthy",
          securityState: "At Risk",
          isolation: "Not isolated",
          logging: "Active",
          activeSessions: 1284
        },
        {
          id: "db-prod-01",
          name: "Customer Database",
          type: "Database",
          criticality: "CRITICAL",
          operationalStatus: "Healthy",
          securityState: "Under Investigation",
          isolation: "Not isolated",
          logging: "Active",
          activeSessions: 18
        },
        {
          id: "iam-prod",
          name: "IAM Audit",
          type: "Identity",
          criticality: "HIGH",
          operationalStatus: "Healthy",
          securityState: "Monitoring",
          isolation: "Not isolated",
          logging: "Partial",
          activeSessions: 734
        }
      ],
      services: [
        { id: "portal", name: "Customer Portal", status: "Healthy", businessImpact: "Low", health: 100 },
        { id: "auth", name: "Authentication", status: "Healthy", businessImpact: "Low", health: 100 },
        { id: "database", name: "Database", status: "Healthy", businessImpact: "Low", health: 100 },
        { id: "api", name: "Customer API", status: "Healthy", businessImpact: "Low", health: 100 },
        { id: "support", name: "Support Queue", status: "Healthy", businessImpact: "Low", health: 100 }
      ],
      users: [
        { username: "web_portal_ro", role: "service account", privilege: "read-only database role" },
        { username: "admin", role: "administrator", privilege: "portal administration" },
        { username: "maya.chen", role: "SOC Analyst", privilege: "IR-L2" }
      ],
      groundTruth: {
        successfulExploit: true,
        databaseAccessed: true,
        recordsQueried: 247,
        dataExfiltrated: false,
        persistenceEstablished: true,
        adminCompromised: false,
        attackerIPs: ["198.51.100.24", "203.0.113.18", "192.0.2.44"],
        vulnerableEndpoint: "/customers?id=",
        affectedTables: ["users", "customers"],
        affectedFields: ["name", "email", "phone", "password_hash"],
        disabledTelemetry: ["egress packet capture for db-prod-01"],
        timeline: [
          ["09:08", "Reconnaissance", "Attacker probed /customers and /admin/export"],
          ["09:10", "Initial Access", "SQL injection payload returned abnormal response size"],
          ["09:13", "Collection", "247 rows queried through web_portal_ro"],
          ["09:17", "Persistence", "Attacker attempted lightweight web session persistence"],
          ["09:28", "Defense Evasion", "Attacker prepared alternate source IP"]
        ]
      },
      playerKnowledge: {
        initialFacts: [
          "Possible SQL injection against customer-portal-prod",
          "One suspicious source IP is visible",
          "Database scope is unknown",
          "External exfiltration is unconfirmed",
          "Persistence is unknown"
        ],
        unknowns: [
          "Whether the SQLi payload succeeded",
          "Which data classes were accessed",
          "Whether data left the environment",
          "Whether credentials were reused",
          "Whether attacker persistence exists"
        ]
      },
      objectives: [
        "Validate the WAF alert with independent telemetry",
        "Scope database activity without overclaiming exfiltration",
        "Preserve evidence with hashes and chain of custody",
        "Coordinate containment with business impact awareness",
        "Validate remediation and legal conclusions before closure"
      ],
      tasks: [
        { id: "TASK-001", title: "Preserve WAF logs", owner: "SOC Analyst", status: "Pending", priority: "High", phase: "Detection", dependencies: [], relatedEvidence: ["E-004"] },
        { id: "TASK-002", title: "Scope database activity", owner: "SOC Analyst", status: "Pending", priority: "High", phase: "Investigation", dependencies: ["TASK-001"], relatedEvidence: ["E-005"] },
        { id: "TASK-003", title: "Check outbound telemetry", owner: "SOC Analyst", status: "Pending", priority: "Medium", phase: "Investigation", dependencies: ["TASK-002"], relatedEvidence: [] },
        { id: "TASK-004", title: "Rotate database credential", owner: "Incident Commander", status: "Pending", priority: "High", phase: "Containment", dependencies: ["TASK-002"], relatedEvidence: [] },
        { id: "TASK-005", title: "Deploy parameterized query patch", owner: "AppSec Engineer", status: "Pending", priority: "High", phase: "Remediation", dependencies: ["TASK-002"], relatedEvidence: [] },
        { id: "TASK-006", title: "Determine legal notification posture", owner: "Legal/Compliance", status: "Pending", priority: "High", phase: "Legal", dependencies: ["TASK-002"], relatedEvidence: ["E-005", "E-008"] }
      ],
      evidence: [
        { id: "E-003", name: "HTTP exploit request", type: "HTTP log", source: "web-prod-01", sourceLog: "HTTPLogs", eventSelector: { event_id: "HTTP-8841" } },
        { id: "E-004", name: "WAF SQL injection alert", type: "WAF alert", source: "edge-waf-02", sourceLog: "WAFLogs", eventSelector: { event_id: "WAF-1192" } },
        { id: "E-005", name: "Database audit export", type: "Database audit", source: "db-prod-01", sourceLog: "DatabaseLogs", eventSelector: { event_id: "DB-8841" } },
        { id: "E-006", name: "IAM admin login review", type: "IAM audit", source: "iam-prod", sourceLog: "AuthLogs", eventSelector: { event_id: "IAM-2210" } },
        { id: "E-008", name: "Customer support complaint cluster", type: "Support record", source: "support-queue", sourceLog: "SupportDesk", eventSelector: { event_id: "SUP-7782" } }
      ],
      hypotheses: [
        {
          id: "HYP-001",
          title: "SQL injection succeeded",
          status: "Possible",
          baseConfidence: 28,
          supportingEvidence: ["E-003", "E-004"],
          confirmingEvidence: ["E-005"],
          contradictions: []
        },
        {
          id: "HYP-002",
          title: "Customer rows were queried",
          status: "Needs More Evidence",
          baseConfidence: 22,
          supportingEvidence: ["E-005"],
          confirmingEvidence: ["E-003", "E-004"],
          contradictions: []
        },
        {
          id: "HYP-003",
          title: "Data was exfiltrated",
          status: "Possible",
          baseConfidence: 14,
          supportingEvidence: ["E-005"],
          confirmingEvidence: [],
          contradictions: ["No outbound proxy evidence", "DB egress packet capture disabled"]
        },
        {
          id: "HYP-004",
          title: "Administrator credential compromised",
          status: "Needs More Evidence",
          baseConfidence: 16,
          supportingEvidence: ["E-006"],
          confirmingEvidence: [],
          contradictions: ["No successful admin login confirmed"]
        },
        {
          id: "HYP-005",
          title: "Insider involvement",
          status: "Unlikely",
          baseConfidence: 4,
          supportingEvidence: [],
          confirmingEvidence: [],
          contradictions: ["External source IP and WAF SQLi pattern identified"]
        }
      ],
      expectedTechniques: [
        {
          id: "T1190",
          tactic: "Initial Access",
          technique: "Exploit Public-Facing Application",
          activity: "SQL injection against /customers?id=",
          evidence: ["E-003", "E-004"],
          telemetry: ["WAFLogs", "HTTPLogs", "ApplicationLogs"],
          response: "Targeted WAF block and root-cause patch"
        },
        {
          id: "T1083",
          tactic: "Discovery",
          technique: "File and Directory Discovery",
          activity: "Route probing for /admin/export and customer endpoints",
          evidence: ["E-003"],
          telemetry: ["HTTPLogs"],
          response: "Hunt source IP and user-agent across web logs"
        },
        {
          id: "T1005",
          tactic: "Collection",
          technique: "Data from Local System",
          activity: "Customer rows queried via application database role",
          evidence: ["E-005"],
          telemetry: ["DatabaseLogs"],
          response: "Preserve DB audit and scope accessed fields"
        },
        {
          id: "T1078",
          tactic: "Defense Evasion",
          technique: "Valid Accounts",
          activity: "Possible follow-on admin login attempts",
          evidence: ["E-006"],
          telemetry: ["AuthLogs", "IAM"],
          response: "Review failed/successful authentication before declaring compromise"
        }
      ],
      scoringRules: [
        { id: "score-evidence", metric: "Evidence Preservation", evidence: ["E-003", "E-004", "E-005"], weight: 30 },
        { id: "score-uncertainty", metric: "Legal Accuracy", rule: "Do not claim exfiltration without egress evidence", weight: 20 },
        { id: "score-containment", metric: "Containment", actions: ["waf_block", "patch_deployed"], weight: 30 }
      ],
      detectionGaps: [
        {
          id: "GAP-001",
          title: "Outbound proxy logging missing for db-prod-01",
          impact: "Data exfiltration cannot be conclusively determined from current telemetry.",
          recommendation: "Enable centralized egress logging for database subnets."
        },
        {
          id: "GAP-002",
          title: "IAM clock skew across edge logs",
          impact: "Authentication correlation has a 90 second uncertainty window.",
          recommendation: "Enforce NTP drift alerts for IAM and WAF systems."
        }
      ]
    },
    scenarioSeed("ransomware-ad", "Ransomware / Active Directory Compromise", "Endpoint and Identity Compromise", "Advanced", "Active Directory, workstations, backup server", ["SOC Analyst", "Incident Commander", "Legal/Compliance"]),
    scenarioSeed("phishing-account-takeover", "Phishing / Account Takeover", "Identity Compromise", "Beginner", "Email gateway, IAM, VPN, cloud mailbox", ["SOC Analyst", "Incident Commander", "Legal/Compliance"]),
    scenarioSeed("business-email-compromise", "Business Email Compromise", "Fraud and Identity", "Intermediate", "Mailbox, finance workflow, executive communications", ["SOC Analyst", "Incident Commander", "Legal/Compliance"]),
    scenarioSeed("cloud-credential-leak", "Cloud Credential Leak", "Cloud Compromise", "Advanced", "Cloud IAM, object storage, CI/CD secrets", ["SOC Analyst", "Incident Commander", "AppSec Engineer"]),
    scenarioSeed("insider-exfiltration", "Insider Data Exfiltration", "Insider Threat", "Advanced", "Endpoint, DLP, database, HR/legal workflow", ["SOC Analyst", "Incident Commander", "Legal/Compliance"]),
    scenarioSeed("webshell-compromise", "Web Shell / Public Server Compromise", "Server Compromise", "Advanced", "Linux web server, EDR, proxy, WAF", ["SOC Analyst", "Incident Commander", "AppSec Engineer"]),
    scenarioSeed("supply-chain-compromise", "Supply Chain Compromise", "Software Supply Chain", "Expert", "CI/CD, package registry, production API", ["SOC Analyst", "Incident Commander", "AppSec Engineer", "Legal/Compliance"])
  ];

  function scenarioSeed(id, title, category, difficulty, environment, availableRoles) {
    return {
      id,
      incidentId: `INC-${id.toUpperCase().replace(/[^A-Z0-9]+/g, "-").slice(0, 18)}`,
      title,
      description: `${title} exercise seed with scenario-driven alerts, assets, hypotheses, and synthetic telemetry.`,
      difficulty,
      category,
      complexity: difficulty === "Expert" ? "multi-stage investigation" : "guided investigation",
      environment,
      availableRoles,
      referenceImplementation: false,
      seed: `${id}-seed`,
      initialAlerts: [
        { id: `ALERT-${id}-001`, source: "SIEM", title, severity: difficulty === "Beginner" ? "MEDIUM" : "HIGH", asset: environment.split(",")[0], summary: "Initial alert requires validation before conclusions are drawn." }
      ],
      assets: [
        { id: `${id}-primary`, name: environment.split(",")[0], type: category, criticality: "HIGH", operationalStatus: "Healthy", securityState: "Suspicious", isolation: "Not isolated", logging: "Active", activeSessions: 42 },
        { id: `${id}-supporting`, name: environment.split(",")[1] || "Supporting telemetry", type: "Telemetry", criticality: "MEDIUM", operationalStatus: "Healthy", securityState: "Monitoring", isolation: "Not isolated", logging: "Partial", activeSessions: 8 }
      ],
      services: [
        { id: "primary", name: environment.split(",")[0], status: "Healthy", businessImpact: "Low", health: 100 },
        { id: "identity", name: "Identity", status: "Healthy", businessImpact: "Low", health: 100 }
      ],
      groundTruth: {
        successfulExploit: difficulty !== "Beginner",
        dataExfiltrated: difficulty === "Expert",
        persistenceEstablished: difficulty !== "Beginner",
        attackerIPs: ["203.0.113.77", "198.51.100.82"],
        recordsQueried: difficulty === "Beginner" ? 0 : 118
      },
      playerKnowledge: {
        initialFacts: ["Initial alert requires validation", "Scope is unknown", "Business impact is unknown"],
        unknowns: ["Whether the alert is true positive", "Whether data was accessed", "Whether containment will affect operations"]
      },
      tasks: [
        { id: "TASK-001", title: "Validate initial alert", owner: "SOC Analyst", status: "Pending", priority: "High", phase: "Detection", dependencies: [], relatedEvidence: [] },
        { id: "TASK-002", title: "Scope affected environment", owner: "SOC Analyst", status: "Pending", priority: "High", phase: "Investigation", dependencies: ["TASK-001"], relatedEvidence: [] },
        { id: "TASK-003", title: "Recommend containment", owner: "Incident Commander", status: "Pending", priority: "Medium", phase: "Containment", dependencies: ["TASK-002"], relatedEvidence: [] }
      ],
      evidence: [],
      hypotheses: [
        { id: "HYP-001", title: "Initial alert represents real compromise", status: "Needs More Evidence", baseConfidence: 20, supportingEvidence: [], confirmingEvidence: [], contradictions: [] },
        { id: "HYP-002", title: "Business impact is limited", status: "Possible", baseConfidence: 18, supportingEvidence: [], confirmingEvidence: [], contradictions: ["Scope incomplete"] }
      ],
      expectedTechniques: [],
      scoringRules: [],
      detectionGaps: [
        { id: "GAP-001", title: "Scenario telemetry is intentionally incomplete", impact: "Players must distinguish unknowns from confirmed facts.", recommendation: "Collect supporting logs before declaring final scope." }
      ]
    };
  }

  const FIELD_ALIASES = {
    sourceip: "src_ip",
    srcip: "src_ip",
    ip: "src_ip",
    source_ip: "src_ip",
    username: "username",
    user: "username",
    account: "username",
    hostname: "hostname",
    host: "hostname",
    computer: "hostname",
    uri: "uri",
    url: "uri",
    path: "uri",
    eventtype: "event_type",
    event_type: "event_type",
    source: "source",
    sourcetype: "source",
    table: "table",
    recordsread: "records_read",
    records_read: "records_read",
    eventid: "event_id",
    event_id: "event_id",
    result: "result",
    action: "action",
    severity: "severity",
    sessionid: "session_id",
    session_id: "session_id",
    useragent: "user_agent",
    user_agent: "user_agent"
  };

  function deepClone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#39;"
    })[char]);
  }

  function hashSeed(seed) {
    let hash = 2166136261;
    String(seed || "incident").split("").forEach(char => {
      hash ^= char.charCodeAt(0);
      hash = Math.imul(hash, 16777619);
    });
    return hash >>> 0;
  }

  function seededRandom(seed) {
    let value = hashSeed(seed) || 1;
    return function nextRandom() {
      value ^= value << 13;
      value ^= value >>> 17;
      value ^= value << 5;
      return ((value >>> 0) % 100000) / 100000;
    };
  }

  function pick(random, values) {
    return values[Math.floor(random() * values.length) % values.length];
  }

  function pad(value) {
    return String(value).padStart(2, "0");
  }

  function timestampAt(offsetSeconds) {
    const base = new Date("2026-08-25T09:08:00Z");
    return new Date(base.getTime() + offsetSeconds * 1000).toISOString();
  }

  function timeLabel(timestamp) {
    const date = new Date(timestamp);
    return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
  }

  function normalizeField(field) {
    const key = String(field || "").replace(/[^a-zA-Z0-9_]/g, "").toLowerCase();
    return FIELD_ALIASES[key] || key;
  }

  function readField(row, field) {
    const normalized = normalizeField(field);
    if (Object.prototype.hasOwnProperty.call(row, normalized)) return row[normalized];
    const direct = Object.keys(row).find(key => key.toLowerCase() === normalized.toLowerCase());
    return direct ? row[direct] : undefined;
  }

  function compareValues(left, operator, right) {
    const value = left === undefined || left === null ? "" : String(left);
    const target = String(right ?? "");
    if (operator === "contains") return value.toLowerCase().includes(target.toLowerCase());
    if (operator === "!=") return value.toLowerCase() !== target.toLowerCase();
    if (operator === ">" || operator === "<" || operator === ">=" || operator === "<=") {
      const a = Number(value);
      const b = Number(target);
      if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
      if (operator === ">") return a > b;
      if (operator === "<") return a < b;
      if (operator === ">=") return a >= b;
      if (operator === "<=") return a <= b;
    }
    return value.toLowerCase() === target.toLowerCase();
  }

  function canonicalStringify(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
    if (value && typeof value === "object") {
      return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalStringify(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
  }

  async function sha256Hex(payload) {
    const subtle = window.crypto && window.crypto.subtle;
    if (!subtle || !window.TextEncoder) return "sha256-unavailable";
    const bytes = new TextEncoder().encode(payload);
    const digest = await subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, "0")).join("");
  }

  function createSqlInjectionTelemetry(scenario, difficulty, seed) {
    const random = seededRandom(`${scenario.seed}:${seed}:${difficulty.label}`);
    const rows = [];
    const benignIps = ["198.51.100.70", "203.0.113.8", "192.0.2.18", "198.51.100.88", "203.0.113.44"];
    const paths = ["/", "/customers?id=12", "/customers?id=13", "/billing", "/profile", "/support", "/api/session"];
    const users = ["customer-128", "customer-219", "customer-441", "anonymous", "support-api"];

    for (let index = 0; index < 520; index += 1) {
      const offset = Math.floor(random() * 3600);
      const ip = random() < 0.08 ? "198.51.100.24" : pick(random, benignIps);
      const uri = pick(random, paths);
      rows.push({
        event_id: `HTTP-${1000 + index}`,
        timestamp: timestampAt(offset),
        hostname: "web-prod-01",
        src_ip: ip,
        dst_ip: "10.20.4.17",
        src_port: 42000 + Math.floor(random() * 18000),
        dst_port: 443,
        username: pick(random, users),
        event_type: "http_request",
        source: "HTTPLogs",
        http_method: "GET",
        uri,
        status_code: random() < 0.94 ? 200 : 404,
        bytes_sent: 410 + Math.floor(random() * 1400),
        bytes_received: 720 + Math.floor(random() * 2200),
        process: "nginx",
        parent_process: "systemd",
        command_line: "",
        action: "allowed",
        result: "success",
        severity: "LOW",
        country: ip.startsWith("198.51") ? "NL" : "US",
        user_agent: pick(random, ["Mozilla/5.0", "curl/8.1", "MobileSafari/17", "python-requests/2.31"]),
        session_id: `sess-${Math.floor(random() * 90000).toString(16)}`
      });
    }

    const suspicious = [
      {
        event_id: "HTTP-8838",
        offset: 127,
        source: "HTTPLogs",
        hostname: "web-prod-01",
        src_ip: "198.51.100.24",
        uri: "/admin/export",
        status_code: 403,
        bytes_received: 822,
        severity: "MEDIUM",
        event_type: "http_request",
        action: "denied",
        username: "anonymous",
        user_agent: "sqlmap/1.7",
        session_id: "sess-a91f",
        signalKey: "admin-route-probe",
        summary: "Attacker probed export route before SQLi payload"
      },
      {
        event_id: "HTTP-8841",
        offset: 148,
        source: "HTTPLogs",
        hostname: "web-prod-01",
        src_ip: "198.51.100.24",
        uri: "/customers?id=12 UNION SELECT email,password_hash FROM users--",
        status_code: 200,
        bytes_received: 48212,
        severity: "HIGH",
        event_type: "http_request",
        action: "allowed",
        username: "anonymous",
        user_agent: "sqlmap/1.7",
        session_id: "sess-a91f",
        signalKey: "sql-exploit-http",
        evidenceId: "E-003",
        summary: "SQLi payload returned abnormal response size"
      },
      {
        event_id: "WAF-1192",
        offset: 155,
        source: "WAFLogs",
        hostname: "edge-waf-02",
        src_ip: "198.51.100.24",
        dst_ip: "10.20.4.17",
        uri: "/customers?id=12 UNION SELECT email,password_hash FROM users--",
        event_type: "waf_alert",
        action: "monitor",
        status_code: 200,
        severity: "HIGH",
        rule: "SQLI_GENERIC_17",
        confidence: 63,
        user_agent: "sqlmap/1.7",
        session_id: "sess-a91f",
        signalKey: "waf-sqli",
        evidenceId: "E-004",
        summary: "WAF signature matched UNION SELECT and SQL comment marker"
      },
      {
        event_id: "DB-8841",
        offset: 224,
        source: "DatabaseLogs",
        hostname: "db-prod-01",
        src_ip: "10.20.4.17",
        dst_ip: "10.20.6.21",
        username: "web_portal_ro",
        event_type: "database_query",
        table: "users",
        records_read: 247,
        query_hash: "qh_83af22",
        action: "select",
        result: "success",
        severity: "HIGH",
        session_id: "sess-a91f",
        signalKey: "db-row-scan",
        evidenceId: "E-005",
        summary: "web_portal_ro read 247 user rows through customer portal path"
      },
      {
        event_id: "IAM-2210",
        offset: 1148,
        source: "AuthLogs",
        hostname: "iam-prod",
        src_ip: "198.51.100.24",
        username: "admin",
        event_type: "authentication",
        result: "failed",
        action: "login",
        severity: "MEDIUM",
        country: "NL",
        session_id: "auth-7f3a",
        signalKey: "admin-follow-on",
        evidenceId: "E-006",
        summary: "Admin failed login from suspicious ASN after DB access"
      },
      {
        event_id: "SUP-7782",
        offset: 682,
        source: "SupportDesk",
        hostname: "support-queue",
        src_ip: "n/a",
        username: "support-agent-04",
        event_type: "customer_complaint",
        result: "open",
        action: "ticket_created",
        severity: "MEDIUM",
        ticket_count: 7,
        signalKey: "customer-impact",
        evidenceId: "E-008",
        summary: "Customers reported seeing another customer's profile data"
      }
    ];

    suspicious.forEach(row => {
      rows.push({
        dst_ip: "10.20.4.17",
        src_port: 44312,
        dst_port: 443,
        http_method: "GET",
        bytes_sent: 1260,
        process: row.source === "DatabaseLogs" ? "postgres" : row.source === "AuthLogs" ? "idp-service" : "nginx",
        parent_process: "systemd",
        command_line: "",
        country: "NL",
        timestamp: timestampAt(row.offset),
        ...row
      });
    });

    for (let index = 0; index < Math.round(80 * difficulty.falsePositiveRate); index += 1) {
      rows.push({
        event_id: `FP-${index}`,
        timestamp: timestampAt(180 + Math.floor(random() * 1900)),
        hostname: pick(random, ["finance-admin", "marketing-laptop", "workstation-23", "vpn-gateway"]),
        src_ip: pick(random, benignIps),
        dst_ip: pick(random, ["10.44.8.91", "10.18.42.23", "10.12.1.10"]),
        username: pick(random, ["finance.user", "it.deploy", "marketing.ops", "vpn-user"]),
        event_type: pick(random, ["authentication", "dns_query", "powershell", "proxy_request"]),
        source: pick(random, ["AuthLogs", "DNSLogs", "EDR", "ProxyLogs"]),
        uri: pick(random, ["/sso", "/inventory", "tracking-cdn.example", "/updates"]),
        status_code: 200,
        action: random() < 0.5 ? "allowed" : "blocked",
        result: random() < 0.7 ? "success" : "failed",
        severity: pick(random, ["LOW", "MEDIUM"]),
        process: pick(random, ["powershell.exe", "chrome.exe", "vpnclient", "software-deploy.exe"]),
        parent_process: pick(random, ["explorer.exe", "software-deploy.exe", "systemd"]),
        command_line: random() < 0.3 ? "powershell.exe -File inventory.ps1" : "",
        user_agent: "Mozilla/5.0",
        session_id: `fp-${index.toString(16)}`,
        summary: "Competing alert requiring triage"
      });
    }

    if (difficulty.logCompleteness < 0.8) {
      rows.push({
        event_id: "GAP-DB-EGRESS",
        timestamp: timestampAt(900),
        hostname: "db-prod-01",
        src_ip: "10.20.6.21",
        dst_ip: "unknown",
        username: "system",
        source: "DetectionGaps",
        event_type: "log_gap",
        action: "telemetry_missing",
        result: "unknown",
        severity: "MEDIUM",
        summary: "Outbound proxy logging was not enabled for db-prod-01"
      });
    }

    return rows.sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
  }

  function createGenericTelemetry(scenario, difficulty, seed) {
    const random = seededRandom(`${scenario.seed}:${seed}:${difficulty.label}`);
    const rows = [];
    const sources = ["SIEM", "AuthLogs", "EDR", "ProxyLogs", "DNSLogs", "FirewallLogs", "CloudLogs"];
    for (let index = 0; index < 360; index += 1) {
      rows.push({
        event_id: `${scenario.id.toUpperCase()}-${index}`,
        timestamp: timestampAt(Math.floor(random() * 3200)),
        hostname: pick(random, scenario.assets.map(asset => asset.id).concat(["workstation-034", "vpn-gateway", "cloud-prod"])),
        src_ip: pick(random, ["203.0.113.77", "198.51.100.82", "10.18.4.12", "10.42.9.18"]),
        dst_ip: pick(random, ["10.20.4.17", "10.20.6.21", "10.0.12.44"]),
        username: pick(random, ["administrator", "service-api", "j.miller", "finance.ops", "cloud-ci"]),
        source: pick(random, sources),
        event_type: pick(random, ["authentication", "process", "network", "cloud_api", "file_access"]),
        action: pick(random, ["allowed", "blocked", "failed", "created", "read"]),
        result: pick(random, ["success", "failed", "unknown"]),
        severity: random() < difficulty.falsePositiveRate ? "MEDIUM" : "LOW",
        uri: pick(random, ["/sso", "/api/token", "/files/export", "/admin"]),
        process: pick(random, ["powershell.exe", "bash", "python", "chrome.exe", "aws"]),
        command_line: random() < 0.12 ? "encoded command observed" : "",
        session_id: `sess-${Math.floor(random() * 100000).toString(16)}`,
        summary: "Scenario telemetry event"
      });
    }
    rows.push({
      event_id: `${scenario.id.toUpperCase()}-TRUE-1`,
      timestamp: timestampAt(220),
      hostname: scenario.assets[0]?.id || "primary-asset",
      src_ip: scenario.groundTruth.attackerIPs[0],
      dst_ip: "10.20.4.17",
      username: "service-api",
      source: "SIEM",
      event_type: "scenario_signal",
      action: "observed",
      result: "requires_validation",
      severity: "HIGH",
      summary: scenario.initialAlerts[0]?.summary || "Initial alert requires validation",
      signalKey: "scenario-primary"
    });
    return rows.sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
  }

  function createTelemetry(scenario, difficulty, seed) {
    if (scenario.id === "sql-injection") return createSqlInjectionTelemetry(scenario, difficulty, seed);
    return createGenericTelemetry(scenario, difficulty, seed);
  }

  function createRuntime(scenarioId = "sql-injection", options = {}) {
    const scenario = deepClone(EMBEDDED_SCENARIOS.find(item => item.id === scenarioId) || EMBEDDED_SCENARIOS[0]);
    const difficulty = DIFFICULTY_MODES[options.difficulty] || DIFFICULTY_MODES[scenario.difficulty] || DIFFICULTY_MODES.Intermediate;
    const seed = options.seed || scenario.seed || scenario.id;
    const groundTruth = deepClone(scenario.groundTruth || {});
    const telemetry = createTelemetry(scenario, difficulty, seed);
    const playerKnowledge = deepClone(scenario.playerKnowledge || { initialFacts: [], unknowns: [] });
    const assets = deepClone(scenario.assets || []);
    const services = deepClone(scenario.services || []);
    const tasks = deepClone(scenario.tasks || []);
    const hypotheses = deepClone(scenario.hypotheses || []);
    const evidenceRecords = {};
    const iocs = [];
    const defenderActions = [];
    const eventFlags = {};
    const attacker = {
      stage: "Reconnaissance",
      currentIp: groundTruth.attackerIPs?.[0] || "203.0.113.77",
      visibility: "partial",
      pressure: difficulty.attackerPressure,
      persistenceActive: Boolean(groundTruth.persistenceEstablished),
      infrastructureIndex: 0
    };

    if (options.snapshot) restore(options.snapshot);

    function addKnowledge(kind, value, confidence = "Possible", evidenceId = null) {
      const exists = playerKnowledge.initialFacts.some(item => item === value);
      if (!exists) playerKnowledge.initialFacts.push(value);
      if (kind === "ioc" && value && !iocs.some(item => item.value === value)) {
        iocs.push({ type: value.includes(".") ? "ip" : "indicator", value, confidence, evidenceId, firstSeen: new Date().toISOString() });
      }
    }

    function discoveriesFromRows(rows) {
      const discoveries = [];
      rows.forEach(row => {
        if (row.src_ip && groundTruth.attackerIPs?.includes(row.src_ip)) {
          addKnowledge("ioc", row.src_ip, "Likely", row.evidenceId || null);
          discoveries.push(`IOC observed: ${row.src_ip}`);
        }
        if (row.signalKey === "sql-exploit-http") discoveries.push("HTTP evidence suggests the SQLi payload reached the app and returned an abnormal response.");
        if (row.signalKey === "waf-sqli") discoveries.push("WAF evidence supports SQL injection activity but does not prove data exfiltration.");
        if (row.signalKey === "db-row-scan") discoveries.push("Database audit confirms 247 rows were queried through the web role.");
        if (row.signalKey === "customer-impact") discoveries.push("Customer complaints support business impact, but do not prove external exfiltration.");
      });
      return Array.from(new Set(discoveries));
    }

    function parseQuery(rawQuery) {
      const query = String(rawQuery || "").trim();
      const parts = query.split("|").map(part => part.trim()).filter(Boolean);
      const parsed = {
        original: query,
        source: null,
        filters: [],
        sort: null,
        limit: 50,
        project: null,
        aggregate: null,
        freeText: null
      };
      if (!parts.length) return parsed;

      const first = parts[0];
      if (/^search\b/i.test(first)) {
        const body = first.replace(/^search\s*/i, "").trim();
        const keyValue = body.match(/^([a-zA-Z0-9_.-]+)\s*=\s*"?([^"]+)"?$/);
        const legacyIp = body.match(/^(ip|src_ip|source_ip)\s+([0-9.]+)$/i);
        const legacyUser = body.match(/^(user|username)\s+([a-zA-Z0-9_.-]+)$/i);
        if (keyValue) parsed.filters.push({ field: keyValue[1], operator: "==", value: keyValue[2] });
        else if (legacyIp) parsed.filters.push({ field: "src_ip", operator: "==", value: legacyIp[2] });
        else if (legacyUser) parsed.filters.push({ field: "username", operator: "==", value: legacyUser[2] });
        else parsed.freeText = body.replace(/^"|"$/g, "");
      } else {
        parsed.source = first;
      }

      parts.slice(1).forEach(part => {
        const where = part.match(/^where\s+([a-zA-Z0-9_.-]+)\s*(==|=|!=|contains|>=|<=|>|<)\s*"?([^"]+)"?$/i);
        const sort = part.match(/^sort\s+([a-zA-Z0-9_.-]+)(?:\s+(asc|desc))?$/i);
        const project = part.match(/^(?:project|fields)\s+(.+)$/i);
        const take = part.match(/^(?:take|limit)\s+(\d+)$/i);
        const summarize = part.match(/^(?:summarize|stats)\s+count\s+by\s+([a-zA-Z0-9_.-]+)$/i);
        if (where) parsed.filters.push({ field: where[1], operator: where[2] === "=" ? "==" : where[2].toLowerCase(), value: where[3] });
        else if (sort) parsed.sort = { field: sort[1], direction: (sort[2] || "asc").toLowerCase() };
        else if (project) parsed.project = project[1].split(",").map(field => field.trim()).filter(Boolean);
        else if (take) parsed.limit = Math.max(1, Math.min(200, Number(take[1]) || 50));
        else if (summarize) parsed.aggregate = { type: "count", field: summarize[1] };
      });
      return parsed;
    }

    function queryTelemetry(rawQuery) {
      const parsed = parseQuery(rawQuery);
      let rows = telemetry.slice();
      if (parsed.source) {
        rows = rows.filter(row => String(row.source || "").toLowerCase() === parsed.source.toLowerCase());
      }
      parsed.filters.forEach(filter => {
        rows = rows.filter(row => compareValues(readField(row, filter.field), filter.operator, filter.value));
      });
      if (parsed.freeText) {
        const text = parsed.freeText.toLowerCase();
        rows = rows.filter(row => canonicalStringify(row).toLowerCase().includes(text));
      }
      if (difficulty.label === "Expert") {
        rows = rows.filter(row => row.source !== "DetectionGaps" || parsed.original.toLowerCase().includes("gap"));
      }
      if (parsed.sort) {
        rows.sort((a, b) => {
          const av = readField(a, parsed.sort.field);
          const bv = readField(b, parsed.sort.field);
          const compare = String(av ?? "").localeCompare(String(bv ?? ""), undefined, { numeric: true });
          return parsed.sort.direction === "desc" ? -compare : compare;
        });
      }
      const total = rows.length;
      let aggregate = null;
      if (parsed.aggregate) {
        const counts = new Map();
        rows.forEach(row => {
          const value = String(readField(row, parsed.aggregate.field) ?? "unknown");
          counts.set(value, (counts.get(value) || 0) + 1);
        });
        aggregate = Array.from(counts.entries())
          .map(([value, count]) => ({ value, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 25);
      }
      const limited = rows.slice(0, parsed.limit);
      const discoveries = discoveriesFromRows(limited);
      const hint = buildQueryHint(parsed, limited);
      return {
        query: parsed.original,
        rows: limited,
        total,
        aggregate,
        discoveries,
        fields: parsed.project || ["timestamp", "source", "hostname", "src_ip", "username", "event_type", "action", "severity", "summary"],
        hint
      };
    }

    function buildQueryHint(parsed, rows) {
      if (difficulty.hints === "none") return "";
      if (!rows.length) return difficulty.hints === "direct"
        ? "No rows matched. Try searching src_ip, username, hostname, source, or broader free text."
        : "No matching telemetry in current sources.";
      const hasAttackerIp = rows.some(row => groundTruth.attackerIPs?.includes(row.src_ip));
      const hasDb = rows.some(row => row.source === "DatabaseLogs");
      if (difficulty.hints === "direct") {
        if (hasAttackerIp && !hasDb) return "Recommended next step: pivot this source IP across WAF, HTTP, AuthLogs, and DatabaseLogs.";
        if (hasDb) return "Recommended next step: collect DB audit evidence and check for egress telemetry before discussing exfiltration.";
        return "Recommended next step: sort by timestamp and inspect source, username, URI, and session_id pivots.";
      }
      if (hasAttackerIp) return "Related telemetry may exist in WAF, HTTP, IAM, and database logs.";
      return "Consider whether this result explains the original alert or is competing noise.";
    }

    function formatTerminalResult(result) {
      if (result.aggregate) {
        return result.aggregate.map(row => `${row.value}: ${row.count}`).join("\n") || "no aggregate rows";
      }
      const rows = result.rows.slice(0, 12);
      const lines = rows.map(row => {
        const time = row.timestamp ? timeLabel(row.timestamp) : "--:--:--";
        return `${time} ${row.source} ${row.hostname || "-"} ${row.src_ip || "-"} ${row.username || "-"} ${row.event_type || "-"} ${row.severity || "-"} ${row.summary || row.uri || row.action || ""}`;
      });
      const suffix = result.total > rows.length ? `\n... ${result.total - rows.length} more rows. Open SIEM for table view.` : "";
      const discoveries = result.discoveries.length ? `\nDISCOVERIES:\n${result.discoveries.map(item => `- ${item}`).join("\n")}` : "";
      const hint = result.hint ? `\nHINT: ${result.hint}` : "";
      return `${result.total} events matched\n${lines.join("\n")}${suffix}${discoveries}${hint}`;
    }

    async function preserveEvidence(eventLike, meta = {}) {
      const sourceEvent = eventLike && eventLike.event_id
        ? eventLike
        : telemetry.find(row => row.evidenceId === eventLike?.id || row.event_id === eventLike?.event_id) || eventLike || {};
      const evidenceId = eventLike?.id || sourceEvent.evidenceId || sourceEvent.event_id || `E-${Object.keys(evidenceRecords).length + 1}`;
      const payload = canonicalStringify({
        evidenceId,
        sourceEvent,
        incidentId: scenario.incidentId,
        scenarioId: scenario.id
      });
      const hash = await sha256Hex(payload);
      const now = meta.timeLabel || new Date().toISOString();
      const record = {
        id: evidenceId,
        name: meta.name || eventLike?.name || sourceEvent.summary || evidenceId,
        type: meta.type || eventLike?.type || sourceEvent.source || "Telemetry",
        source: meta.source || eventLike?.sourceHost || eventLike?.source || sourceEvent.hostname || sourceEvent.source || "unknown",
        collector: meta.collector || "SOC Analyst",
        collectedAt: now,
        originalSize: window.TextEncoder ? new TextEncoder().encode(payload).length : payload.length,
        sha256: hash,
        integrity: hash === "sha256-unavailable" ? "UNAVAILABLE" : "VERIFIED",
        relatedIncident: scenario.incidentId,
        relatedHypothesis: meta.relatedHypothesis || null,
        status: "Relevant",
        notes: meta.notes || "",
        custody: [
          { time: now, actor: meta.collector || "SOC Analyst", action: "COLLECTED", details: "Artifact added to case record" },
          { time: now, actor: "System", action: hash === "sha256-unavailable" ? "HASH UNAVAILABLE" : "HASH VERIFIED", details: hash }
        ],
        sourceEvent
      };
      evidenceRecords[evidenceId] = record;
      return deepClone(record);
    }

    function addCustody(evidenceId, actor, action, details = "") {
      const record = evidenceRecords[evidenceId];
      if (!record) return null;
      record.custody.push({ time: new Date().toISOString(), actor, action, details });
      return deepClone(record);
    }

    function setEvidenceStatus(evidenceId, status, actor = "SOC Analyst") {
      const record = evidenceRecords[evidenceId];
      if (!record) return null;
      record.status = status;
      record.custody.push({ time: new Date().toISOString(), actor, action: `STATUS: ${status.toUpperCase()}`, details: "Non-destructive evidence disposition update" });
      return deepClone(record);
    }

    function updateTask(taskId, status, actor = "System") {
      const task = tasks.find(item => item.id === taskId);
      if (!task) return null;
      task.status = status;
      if (status === "Active" && !task.startedTime) task.startedTime = new Date().toISOString();
      if (status === "Done" && !task.completedTime) task.completedTime = new Date().toISOString();
      task.lastUpdatedBy = actor;
      return deepClone(task);
    }

    function evaluateHypotheses(collectedEvidence = {}) {
      const collected = new Set(Object.keys(collectedEvidence || evidenceRecords));
      return hypotheses.map(hypothesis => {
        const supporting = (hypothesis.supportingEvidence || []).filter(id => collected.has(id));
        const confirming = (hypothesis.confirmingEvidence || []).filter(id => collected.has(id));
        const contradictionPenalty = (hypothesis.contradictions || []).length * 3;
        const confidence = Math.max(1, Math.min(97, Math.round(
          (hypothesis.baseConfidence || 10) +
          supporting.length * 18 +
          confirming.length * 26 -
          contradictionPenalty
        )));
        const evidenceState = confidence >= 85 ? "Confirmed" : confidence >= 65 ? "Likely" : confidence >= 38 ? "Possible" : confidence >= 15 ? "Needs More Evidence" : "Unlikely";
        return {
          ...deepClone(hypothesis),
          calculatedConfidence: confidence,
          suggestedState: evidenceState,
          attachedEvidence: Array.from(collected).filter(id => (hypothesis.supportingEvidence || []).includes(id) || (hypothesis.confirmingEvidence || []).includes(id))
        };
      });
    }

    function recordDefenderAction(type, detail = {}) {
      const action = { type, detail, time: new Date().toISOString() };
      defenderActions.push(action);
      const events = [];
      const asset = id => assets.find(item => item.id === id);
      const service = id => services.find(item => item.id === id);

      if (type === "block_ip") {
        attacker.stage = "Defense Evasion";
        attacker.infrastructureIndex = Math.min((attacker.infrastructureIndex || 0) + 1, (groundTruth.attackerIPs || []).length - 1);
        attacker.currentIp = groundTruth.attackerIPs?.[attacker.infrastructureIndex] || attacker.currentIp;
        events.push({
          id: "attacker-ip-switch",
          severity: "HIGH",
          title: "Attacker changed infrastructure",
          message: `Source-only blocking forced the attacker to switch to ${attacker.currentIp}.`
        });
        telemetry.push({
          event_id: `WAF-SWITCH-${Date.now()}`,
          timestamp: new Date().toISOString(),
          source: "WAFLogs",
          hostname: "edge-waf-02",
          src_ip: attacker.currentIp,
          dst_ip: "10.20.4.17",
          username: "anonymous",
          event_type: "waf_alert",
          action: "monitor",
          severity: "HIGH",
          uri: "/customers?id=12%20UNION%20SELECT",
          summary: "New source IP using similar SQLi payload after source-only block",
          signalKey: "new-attacker-infra"
        });
      }

      if (type === "waf_block") {
        attacker.stage = "Command and Control";
        const waf = asset("edge-waf-02");
        if (waf) waf.securityState = "Blocking";
        events.push({ id: "waf-block-active", severity: "MEDIUM", title: "WAF containment active", message: "SQLi payload success dropped sharply, but follow-on credential use still needs review." });
      }

      if (type === "rotate_db_credential") {
        attacker.stage = "Credential Access";
        const db = asset("db-prod-01");
        const portal = service("portal");
        if (db) db.securityState = "Credential Rotated";
        if (!detail.appSecretUpdated && portal) {
          portal.status = "Degraded";
          portal.health = Math.max(58, portal.health - 28);
          portal.businessImpact = "Medium";
          events.push({ id: "db-rotation-outage", severity: "HIGH", title: "Credential rotation caused portal errors", message: "Database credential rotated before the application secret was updated; HTTP 500 errors increased." });
        } else {
          events.push({ id: "db-rotation-clean", severity: "MEDIUM", title: "Credential replay path reduced", message: "Database credential rotation removed a likely replay path." });
        }
      }

      if (type === "isolate_asset") {
        const target = asset(detail.assetId || "customer-portal-prod");
        if (target) {
          target.isolation = "Isolated";
          target.operationalStatus = "Major Impact";
          target.securityState = "Contained";
        }
        const portal = service("portal");
        if (portal) {
          portal.status = "Major Impact";
          portal.health = Math.max(12, portal.health - 60);
          portal.businessImpact = "High";
        }
        attacker.stage = "Impact";
        events.push({ id: "asset-isolated", severity: "CRITICAL", title: "Asset isolated", message: "Attacker access is reduced, but service availability and some live forensic visibility are lost." });
      }

      if (type === "patch_deployed") {
        attacker.stage = "Impact";
        const portal = service("portal");
        if (portal) {
          portal.status = portal.health < 90 ? "Recovering" : "Healthy";
          portal.health = Math.max(portal.health, 92);
        }
        const app = asset("customer-portal-prod");
        if (app) app.securityState = "Remediated";
        events.push({ id: "patch-effective", severity: "LOW", title: "Exploit path remediated", message: "Parameterized query patch removed the root cause. Continue monitoring for persistence." });
      }
      return events;
    }

    function tick(context = {}) {
      const events = [];
      const elapsed = Number(context.elapsedSeconds || 0);
      if (elapsed > 120 && !eventFlags.collection && !defenderActions.some(action => action.type === "waf_block" || action.type === "isolate_asset")) {
        eventFlags.collection = true;
        attacker.stage = "Collection";
        events.push({ id: "attacker-collection", severity: "HIGH", title: "Attacker progressed to collection", message: "The attacker is attempting broader table enumeration while containment remains incomplete." });
      }
      if (elapsed > 220 && !eventFlags.persistence && attacker.persistenceActive && !defenderActions.some(action => action.type === "patch_deployed")) {
        eventFlags.persistence = true;
        attacker.stage = "Persistence";
        events.push({ id: "attacker-persistence", severity: "HIGH", title: "Possible persistence activity", message: "Application session anomalies suggest the attacker may be preserving access." });
      }
      if (elapsed > 320 && !eventFlags.antiForensics && difficulty.label === "Expert") {
        eventFlags.antiForensics = true;
        attacker.stage = "Defense Evasion";
        events.push({ id: "anti-forensics", severity: "HIGH", title: "Telemetry quality degraded", message: "Clock skew and log gaps make exact reconstruction harder." });
      }
      return events;
    }

    function publicScenario() {
      const copy = deepClone(scenario);
      delete copy.groundTruth;
      return copy;
    }

    function publicState(collectedEvidence = {}) {
      return {
        scenario: publicScenario(),
        difficulty: difficulty.label,
        seed,
        playerKnowledge: deepClone(playerKnowledge),
        assets: deepClone(assets),
        services: deepClone(services),
        tasks: deepClone(tasks),
        hypotheses: evaluateHypotheses(collectedEvidence),
        iocs: deepClone(iocs),
        attacker: {
          stage: attacker.stage,
          visibility: attacker.visibility,
          currentIp: iocs.some(item => item.value === attacker.currentIp) ? attacker.currentIp : "unknown"
        },
        evidenceRecords: deepClone(evidenceRecords),
        detectionGaps: deepClone(scenario.detectionGaps || [])
      };
    }

    function instructorSnapshot() {
      return {
        groundTruth: deepClone(groundTruth),
        attacker: deepClone(attacker),
        defenderActions: deepClone(defenderActions),
        telemetryCount: telemetry.length,
        eventFlags: deepClone(eventFlags)
      };
    }

    function serialize() {
      return {
        scenarioId: scenario.id,
        difficulty: difficulty.label,
        seed,
        playerKnowledge: deepClone(playerKnowledge),
        assets: deepClone(assets),
        services: deepClone(services),
        tasks: deepClone(tasks),
        hypotheses: deepClone(hypotheses),
        evidenceRecords: deepClone(evidenceRecords),
        iocs: deepClone(iocs),
        defenderActions: deepClone(defenderActions),
        attacker: deepClone(attacker),
        eventFlags: deepClone(eventFlags)
      };
    }

    function restore(snapshot) {
      if (!snapshot) return;
      Object.assign(playerKnowledge, deepClone(snapshot.playerKnowledge || {}));
      replaceArray(assets, snapshot.assets);
      replaceArray(services, snapshot.services);
      replaceArray(tasks, snapshot.tasks);
      replaceArray(hypotheses, snapshot.hypotheses);
      Object.assign(evidenceRecords, deepClone(snapshot.evidenceRecords || {}));
      replaceArray(iocs, snapshot.iocs);
      replaceArray(defenderActions, snapshot.defenderActions);
      Object.assign(attacker, deepClone(snapshot.attacker || {}));
      Object.assign(eventFlags, deepClone(snapshot.eventFlags || {}));
    }

    return {
      getScenario: publicScenario,
      getPublicState: publicState,
      getInstructorSnapshot: instructorSnapshot,
      queryTelemetry,
      formatTerminalResult,
      preserveEvidence,
      addCustody,
      setEvidenceStatus,
      updateTask,
      evaluateHypotheses,
      recordDefenderAction,
      tick,
      getTelemetryCount: () => telemetry.length,
      serialize
    };
  }

  function replaceArray(target, source) {
    if (!Array.isArray(source)) return;
    target.splice(0, target.length, ...deepClone(source));
  }

  async function loadCatalog() {
    if (!window.fetch) return deepClone(EMBEDDED_SCENARIOS);
    try {
      const responses = await Promise.all(SCENARIO_FILES.map(file => fetch(file).then(response => response.ok ? response.json() : null).catch(() => null)));
      const fetched = responses.filter(Boolean);
      if (!fetched.length) return deepClone(EMBEDDED_SCENARIOS);
      return EMBEDDED_SCENARIOS.map(embedded => {
        const override = fetched.find(item => item.id === embedded.id);
        return override ? { ...embedded, ...override } : embedded;
      });
    } catch (error) {
      return deepClone(EMBEDDED_SCENARIOS);
    }
  }

  window.IRSimulation = {
    difficultyModes: DIFFICULTY_MODES,
    scenarioFiles: SCENARIO_FILES,
    catalog: deepClone(EMBEDDED_SCENARIOS),
    loadCatalog,
    createRuntime,
    escapeHTML,
    deepClone
  };
})();
