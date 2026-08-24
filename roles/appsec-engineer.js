(function registerAppSecEngineerPartials() {
  window.SimulatorRolePartials = window.SimulatorRolePartials || {};
  window.SimulatorRolePartials.appsecEngineer = {
    leftMetrics: `
        <div class="panel card appsec-only">
          <h2>AppSec Metrics</h2>
          <div class="metrics" id="appsecMetrics" style="margin-top: 12px;"></div>
        </div>`,
    warroom: `
        <section class="panel commander-panel appsec-only">
          <span class="session-badge">APPSEC HANDOFF</span>
          <h2>Application Remediation Overview</h2>
          <p class="small">Read-only incident context from SOC. AppSec owns reproduction, root cause, patch validation, and deployment request.</p>
          <div class="tradeoff-grid" id="appsecWarRoomSummary"></div>
          <div class="actions">
            <button class="btn primary" type="button" data-page-shortcut="appsec">Open AppSec workspace</button>
            <button class="btn" type="button" data-page-shortcut="ai">Ask AI AppSec Assistant</button>
          </div>
        </section>`,
    workspace: `
        <div class="page-section" data-page-section="appsec">
          <section class="panel simulation-card">
            <h2>AppSec Remediation Workspace</h2>
            <p class="small">Reproduce the exploit safely, trace it to code, apply a real fix, validate it, and request deployment approval.</p>
            <div class="workspace-grid">
              <div class="workspace-card">
                <h3>SOC to AppSec Handoff</h3>
                <div id="appsecHandoff" class="readiness-list"></div>
                <div class="actions">
                  <button class="btn primary" id="acceptAppsecHandoffBtn" type="button">Accept handoff</button>
                </div>
              </div>
              <div class="workspace-card">
                <h3>Exploit Reproduction Lab</h3>
                <div class="code-window" id="appsecRepro"></div>
                <div class="actions">
                  <button class="btn" id="runBaselineBtn" type="button">Run baseline</button>
                  <button class="btn primary" id="runExploitBtn" type="button">Run safely</button>
                </div>
              </div>
              <div class="workspace-card">
                <h3>Code inspection</h3>
                <div class="code-window" id="appsecCode"></div>
                <div class="actions">
                  <button class="btn" id="inspectCodeBtn" type="button">Inspect code</button>
                  <button class="btn primary" id="confirmRootCauseBtn" type="button">Confirm root cause</button>
                </div>
              </div>
              <div class="workspace-card">
                <h3>Patch Builder</h3>
                <div id="patchBuilder" class="tool-chain"></div>
                <div class="actions">
                  <button class="btn primary" id="applyPatchBtn" type="button">Apply selected patch</button>
                </div>
              </div>
              <div class="workspace-card">
                <h3>Security Regression Tests</h3>
                <div id="appsecTests" class="readiness-list"></div>
                <div class="actions">
                  <button class="btn" id="testPatchBtn" type="button">Run test suite</button>
                  <button class="btn primary" id="deployPatchBtn" type="button">Request deployment</button>
                </div>
              </div>
              <div class="workspace-card">
                <h3>Deployment Package</h3>
                <div id="deploymentPackage" class="readiness-list"></div>
              </div>
            </div>
          </section>
        </div>`
  };
})();
