(function registerIncidentCommanderPartials() {
  window.SimulatorRolePartials = window.SimulatorRolePartials || {};
  window.SimulatorRolePartials.incidentCommander = {
    leftMetrics: `
        <div class="panel card commander-only">
          <h2>Command Metrics</h2>
          <div class="metrics" id="commandMetrics" style="margin-top: 12px;"></div>
        </div>`,
    warroom: `
        <section class="panel commander-panel commander-only" id="commanderWarRoom">
          <div class="command-bar" id="commanderCommandBar"></div>
          <div class="command-grid">
            <div class="command-card">
              <h2>COMMANDER PRIORITY - Decide containment strategy</h2>
              <p class="small" id="commanderSituation"></p>
              <div class="decision-options" id="commanderDecisionActions"></div>
            </div>
            <div class="command-card">
              <h3>Stakeholders</h3>
              <div class="stakeholder-grid" id="stakeholderStatus"></div>
            </div>
          </div>
          <div>
            <h3>Decision consequences</h3>
            <div class="tradeoff-grid" id="decisionTradeoffs"></div>
          </div>
          <div class="command-card">
            <h3>High-Level Attack Summary</h3>
            <div class="tradeoff-grid" id="commanderAttackSummary"></div>
          </div>
          <div class="command-grid">
            <div class="command-card">
              <h3>Incident timeline</h3>
              <div class="recent-actions" id="commanderTimeline"></div>
            </div>
            <div class="command-card">
              <h3>Decision log</h3>
              <div class="decision-log" id="commanderDecisionLog"></div>
            </div>
          </div>
        </section>`,
    right: `
        <div class="page-section active commander-only" data-page-section="warroom">
        <div class="panel card">
          <h2>Commander Briefings</h2>
          <div class="recent-actions" id="commanderBriefings"></div>
        </div>
        <div class="panel card">
          <h2>Business Impact</h2>
          <div class="status-light-row" id="commanderBusinessImpact"></div>
        </div>
        </div>`
  };
})();
