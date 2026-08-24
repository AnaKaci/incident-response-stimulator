(function registerSocAnalystPartials() {
  window.SimulatorRolePartials = window.SimulatorRolePartials || {};
  window.SimulatorRolePartials.socAnalyst = {
    leftMetrics: `
        <div class="panel card analyst-only">
          <h2>Incident Metrics</h2>
          <div class="metrics" style="margin-top: 12px;">
            <div class="card metric">
              <span class="small">Attacker progress</span>
              <strong id="attackerProgressMetric">0%</strong>
              <div class="bar good"><span id="scoreBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">Risk</span>
              <strong id="risk">44%</strong>
              <div class="bar bad"><span id="riskBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">Evidence</span>
              <strong id="evidence">0%</strong>
              <div class="bar warn"><span id="evidenceBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">Business impact</span>
              <strong id="loss">LOW</strong>
              <div class="bar bad"><span id="lossBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">Assets affected</span>
              <strong id="assetsAffected">1</strong>
              <div class="bar warn"><span id="assetsBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">Records accessed</span>
              <strong id="recordsExposed">Unknown</strong>
              <div class="bar bad"><span id="recordsBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">MTTD</span>
              <strong id="mttdMetric">--</strong>
              <div class="bar good"><span id="mttdBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">MTTC</span>
              <strong id="mttcMetric">--</strong>
              <div class="bar warn"><span id="mttcBar"></span></div>
            </div>
            <div class="card metric">
              <span class="small">Service health</span>
              <strong id="serviceHealthMetric">100%</strong>
              <div class="bar good"><span id="serviceHealthBar"></span></div>
            </div>
          </div>
        </div>`,
    warroomMap: `
        <section class="panel map-panel analyst-only">
          <canvas id="attackMap" aria-label="Animated attack path from attacker to web app, database, SOC, legal, and customers"></canvas>
          <div class="map-label">
            <h2>Attack Path</h2>
            <p class="small" id="mapCaption">SQLi traffic is probing the portal.</p>
          </div>
          <div class="attack-badge" id="attackBadge">LIVE EXPLOIT</div>
          <div class="visual-tools">
            <div class="view-buttons" id="viewButtons" aria-label="Visual view selector">
              <button class="view-btn active" type="button" data-view="attack">Attack path</button>
              <button class="view-btn" type="button" data-view="killchain">Kill chain</button>
              <button class="view-btn" type="button" data-view="data">Data exposure</button>
            </div>
            <div class="node-inspector" id="nodeInspector">
              <strong>Click a system node</strong>
              <p class="small">Inspect attacker, WAF, app, database, SOC, or legal/compliance role.</p>
            </div>
          </div>
          <div class="killchain-detail" id="killchainDetail">
            <strong>Interactive kill chain</strong>
            <p class="small">Switch to Kill chain, then click Recon, Exploit, Enumerate, Contain, or Recover.</p>
          </div>
        </section>`,
    incidentFlow: `
        <div class="page-section active" data-page-section="warroom">
        <section class="panel briefing analyst-only">
          <div>
            <h2>Phase Briefing</h2>
            <p class="small">Each phase shows what the attacker is doing, what defenders must prove, and what business pressure exists in the real incident.</p>
          </div>
          <div class="flow-strip" id="flowStrip"></div>
          <div class="briefing-grid" id="briefingGrid"></div>
        </section>

        <section class="panel incident analyst-only">
          <div class="incident-head">
            <div>
              <div class="pill-row" id="phaseTags"></div>
              <h2 id="phaseTitle" style="margin-top: 8px;"></h2>
            </div>
            <div class="clock" id="clock">09:12</div>
          </div>

          <div class="narrative" id="story"></div>
          <div class="choice-grid" id="choices"></div>
          <div class="outcome" id="outcome" aria-live="polite"></div>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <button class="btn primary" id="next" type="button" disabled>Continue incident</button>
            <button class="btn ghost" id="finish" type="button">Final report</button>
          </div>
        </section>

        <section class="panel simulation-card analyst-only">
          <h2>SOC Terminal</h2>
          <p class="small">Type simulated commands: help, timeline, search ip 198.51.100.24, search user admin, block 198.51.100.24, isolate web-01, snapshot db.</p>
          <div class="soc-terminal">
            <div class="terminal-output" id="socTerminalOutput"></div>
            <div class="terminal-input-row">
              <span>analyst@soc&gt;</span>
              <input id="socCommandInput" type="text" autocomplete="off" placeholder="type command">
              <button class="btn primary" id="socCommandRun" type="button">Run</button>
            </div>
          </div>
        </section>
        </div>`,
    rightFeed: `
        <div class="page-section active analyst-only" data-page-section="warroom">
        <div class="panel feed">
          <h2>Live SOC Feed</h2>
          <div class="feed-list" id="feed"></div>
        </div>

        <div class="panel card">
          <h2>Recent Actions</h2>
          <div class="recent-actions" id="recentActions"></div>
        </div>

        <div class="panel card event-detail">
          <h2>Event Detail</h2>
          <div id="eventDetail" class="small">Click a live SOC event to inspect its source, signal, impact, and recommended response.</div>
        </div>
        </div>`,
    rightInvestigation: `
        <div class="page-section active analyst-only" data-page-section="warroom">
        <div class="panel card event-detail">
          <h2>Interactive Investigation</h2>
          <div class="investigation-grid" id="investigationGrid"></div>
          <div class="small" id="investigationNote">Run quick checks to enrich evidence and reduce uncertainty.</div>
        </div>

        <div class="panel card impact-monitor">
          <h2>Impact Monitor</h2>
          <div class="status-light-row" id="statusLights"></div>
          <div class="heat-list" id="impactHeat"></div>
        </div>
        </div>`,
    rightTranslation: `
        <div class="page-section active analyst-only" data-page-section="warroom">
        <div class="panel card translation">
          <h2>Real-World Translation</h2>
          <p class="small" id="translation"></p>
          <div class="terminal" id="miniTerminal"></div>
        </div>
        </div>`
  };
})();
