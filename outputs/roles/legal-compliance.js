(function registerLegalCompliancePartials() {
  window.SimulatorRolePartials = window.SimulatorRolePartials || {};
  window.SimulatorRolePartials.legalCompliance = {
    leftMetrics: `
        <div class="panel card legal-only">
          <h2>Compliance Metrics</h2>
          <div class="metrics" id="complianceMetrics" style="margin-top: 12px;"></div>
        </div>`,
    workspace: `
        <div class="page-section" data-page-section="legal">
          <section class="panel simulation-card">
            <h2>Data Breach Assessment Workspace</h2>
            <p class="small">Determine what happened to personal data, whether notification duties may apply, what can be communicated, and what evidence must be preserved.</p>
            <div class="workspace-grid">
              <div class="workspace-card">
                <h3>Legal Handoff</h3>
                <div id="legalHandoff" class="readiness-list"></div>
                <div class="actions"><button class="btn primary" id="acceptLegalHandoffBtn" type="button">Accept legal handoff</button></div>
              </div>
              <div class="workspace-card">
                <h3>Regulatory clock</h3>
                <div class="incident-clock" id="regClock">NOT STARTED</div>
                <div id="legalFacts" class="readiness-list"></div>
              </div>
              <div class="workspace-card">
                <h3>Data Classification</h3>
                <div class="role-grid" id="dataClassificationGrid"></div>
              </div>
              <div class="workspace-card">
                <h3>Exposure Assessment</h3>
                <div class="readiness-list" id="exposureAssessment"></div>
                <div class="actions"><button class="btn primary" id="saveExposureBtn" type="button">Save assessment</button></div>
              </div>
              <div class="workspace-card">
                <h3>Regulatory Assessment</h3>
                <div class="readiness-list" id="notificationDecision"></div>
                <textarea id="legalRationale" rows="4" placeholder="Decision rationale"></textarea>
                <div class="actions"><button class="btn primary" id="recordLegalDecisionBtn" type="button">Record legal decision</button></div>
                <div class="small" id="legalDecision"></div>
              </div>
              <div class="workspace-card">
                <h3>Notification Center</h3>
                <div class="readiness-list" id="notificationCenter"></div>
              </div>
            </div>
          </section>
        </div>`
  };
})();
