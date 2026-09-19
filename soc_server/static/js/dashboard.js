// SENTINEL SOC dashboard JS
// Unlike the sensor's own dashboard (live SocketIO feed from a running
// capture), this reads from the central DB via polling — the SOC server
// has no live packet stream of its own, just what sensors have forwarded.

const POLL_INTERVAL_MS = 5000;
let currentRole = null;
let currentNetworkFilter = "";  // "" = no filter (soc_admin "all networks")

function fmtTime(ts) {
  return new Date(ts * 1000).toTimeString().split(" ")[0];
}

function severityClass(sev) {
  return "sev-" + sev;
}

// ---------------- login ----------------

async function tryRestoreSession() {
  const resp = await fetch("/api/me");
  if (resp.ok) {
    const me = await resp.json();
    enterApp(me);
    return true;
  }
  return false;
}

function showLoginError(msg) {
  const el = document.getElementById("login-error");
  el.textContent = msg;
  el.classList.remove("hidden");
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  const resp = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    showLoginError(err.error || "login failed");
    return;
  }
  const me = await resp.json();
  enterApp(me);
}

async function handleLogout() {
  await fetch("/api/logout", { method: "POST" });
  location.reload();
}

function enterApp(me) {
  currentRole = me.role;
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  document.getElementById("user-label").textContent = me.username;
  document.getElementById("role-label").textContent = me.role;

  const switcherWrap = document.getElementById("network-switcher-wrap");
  if (me.role === "soc_admin") {
    switcherWrap.classList.remove("hidden");
    loadNetworkOptions();
  } else {
    switcherWrap.classList.add("hidden");
  }

  refreshData();
  setInterval(refreshData, POLL_INTERVAL_MS);
  startClock();
}

// ---------------- data loading ----------------

async function loadNetworkOptions() {
  const resp = await fetch("/api/networks");
  if (!resp.ok) return;
  const networks = await resp.json();

  const select = document.getElementById("network-switcher");
  // keep the "ALL NETWORKS" option, append the rest
  select.innerHTML = '<option value="">ALL NETWORKS</option>' +
    networks.map((n) => `<option value="${n.name}">${n.name.toUpperCase()}</option>`).join("");

  select.addEventListener("change", () => {
    currentNetworkFilter = select.value;
    refreshData();
  });

  renderNetworksList(networks);
}

function renderNetworksList(networks) {
  const el = document.getElementById("networks-list");
  if (!networks.length) {
    el.innerHTML = '<div class="type-empty">&mdash;</div>';
    return;
  }
  el.innerHTML = networks.map((n) => `
    <div class="type-row">
      <span class="name">${n.name}</span>
    </div>`).join("");
}

function queryString() {
  return currentNetworkFilter ? `?network=${encodeURIComponent(currentNetworkFilter)}` : "";
}

async function refreshData() {
  const [alertsResp, statsResp, behavioralResp, mlResp, incidentsResp] = await Promise.all([
    fetch(`/api/alerts${queryString()}`),
    fetch(`/api/stats${queryString()}`),
    fetch(`/api/behavioral${queryString()}`),
    fetch(`/api/ml-anomalies${queryString()}`),
    fetch(`/api/incidents${queryString()}`),
  ]);

  if (alertsResp.status === 401 || statsResp.status === 401) {
    location.reload();  // session expired — back to login
    return;
  }

  const alerts = await alertsResp.json();
  const stats = await statsResp.json();
  const behavioral = behavioralResp.ok ? await behavioralResp.json() : null;
  const ml = mlResp.ok ? await mlResp.json() : null;
  const incidents = incidentsResp.ok ? await incidentsResp.json() : [];

  renderFeed(alerts);
  renderStats(stats);
  renderBehavioral(behavioral);
  renderMlAnomalies(ml);
  renderIncidents(incidents);
}

function renderMlAnomalies(data) {
  const el = document.getElementById("ml-content");
  if (!data) { el.innerHTML = "&mdash;"; return; }

  const items = Array.isArray(data) ? data : [data];
  el.innerHTML = items.map((r) => {
    const label = r.network_name ? `<div class="kv-row"><span class="k">network</span><span class="v">${r.network_name}</span></div>` : "";
    if (!r.model_trained) {
      return `${label}<div style="color:var(--text-dim);font-size:11px;">${r.reason}</div>`;
    }
    const countColor = r.anomalies_found > 0 ? "var(--critical)" : "var(--signal)";
    let html = `${label}
      <div class="kv-row"><span class="k">flows analyzed</span><span class="v">${r.flows_analyzed}</span></div>
      <div class="kv-row"><span class="k">anomalies</span><span class="v" style="color:${countColor}">${r.anomalies_found}</span></div>`;
    if (r.anomalies.length > 0) {
      const top = r.anomalies[0];
      html += `<div style="margin-top:6px;color:var(--text-dim);font-size:11px;">
        top: score ${top.anomaly_score} &mdash; ${(top.reasons[0] || "")}</div>`;
    }
    return html;
  }).join('<div style="height:10px;border-bottom:1px solid var(--border);margin-bottom:8px;"></div>');
}

function renderIncidents(incidents) {
  const feed = document.getElementById("incidents-feed");
  document.getElementById("incidents-count").textContent = incidents.length;

  if (incidents.length === 0) {
    feed.innerHTML = '<div class="feed-empty">&gt; no correlated incidents yet.</div>';
    return;
  }

  feed.innerHTML = incidents.map((inc) => {
    const sevClass = inc.risk_score >= 70 ? "sev-critical" : inc.risk_score >= 40 ? "sev-high" : "sev-medium";
    return `
      <div class="alert-row ${sevClass}">
        <span class="alert-time">${fmtTime(inc.start_time)}</span>
        <span class="alert-sev">RISK ${inc.risk_score}</span>
        <span class="alert-msg">
          <span class="alert-type-tag">${inc.src_ip}</span><br>
          ${inc.summary}
        </span>
      </div>`;
  }).join("");
}

function renderBehavioral(data) {
  const el = document.getElementById("behavioral-content");
  if (!data) {
    el.innerHTML = "&mdash;";
    return;
  }

  const items = Array.isArray(data) ? data : [data];
  el.innerHTML = items.map((r) => {
    const label = r.network_name ? `<div class="kv-row"><span class="k">network</span><span class="v">${r.network_name}</span></div>` : "";
    const statusColor = r.is_anomaly ? "var(--critical)" : "var(--signal)";
    const statusText = r.is_anomaly ? "ANOMALY" : "normal";
    return `
      ${label}
      <div class="kv-row"><span class="k">status</span><span class="v" style="color:${statusColor}">${statusText}</span></div>
      <div class="kv-row"><span class="k">this hour</span><span class="v">${r.current_hour_count} alerts</span></div>
      <div class="kv-row"><span class="k">baseline avg</span><span class="v">${r.baseline_mean}/hr (${r.sample_hours}h history)</span></div>
      <div class="kv-row"><span class="k">z-score</span><span class="v">${r.z_score}</span></div>
      ${r.reasons.length ? `<div style="margin-top:6px;color:var(--text-dim);font-size:11px;">${r.reasons[0]}</div>` : ""}
    `;
  }).join('<div style="height:10px;border-bottom:1px solid var(--border);margin-bottom:8px;"></div>');
}

function renderFeed(alerts) {
  const feed = document.getElementById("feed");
  document.getElementById("feed-count").textContent = `${alerts.length} event${alerts.length === 1 ? "" : "s"}`;

  if (alerts.length === 0) {
    feed.innerHTML = '<div class="feed-empty" id="feed-empty">&gt; no alerts for this scope yet.</div>';
    return;
  }

  feed.innerHTML = alerts.map((a) => `
    <div class="alert-row ${severityClass(a.severity)}">
      <span class="alert-time">${fmtTime(a.event_timestamp)}</span>
      <span class="alert-sev">${a.severity.toUpperCase()}</span>
      <span class="alert-msg">
        <span class="alert-type-tag">${a.alert_type}</span>
        <span class="alert-src">${a.src_ip}</span><br>
        ${a.message}
      </span>
    </div>
  `).join("");
}

function renderStats(stats) {
  const sevs = ["critical", "high", "medium", "low"];
  const bySev = stats.by_severity || {};
  const maxSev = Math.max(1, ...sevs.map((s) => bySev[s] || 0));

  sevs.forEach((s) => {
    const row = document.querySelector(`.bar-row[data-sev="${s}"]`);
    if (!row) return;
    const count = bySev[s] || 0;
    row.querySelector(".bar-fill").style.width = `${(count / maxSev) * 100}%`;
    row.querySelector(".bar-value").textContent = count;
  });

  const typeList = document.getElementById("type-list");
  const entries = Object.entries(stats.by_type || {}).sort((a, b) => b[1] - a[1]);
  typeList.innerHTML = entries.length === 0
    ? '<div class="type-empty">&mdash;</div>'
    : entries.map(([name, count]) => `
        <div class="type-row"><span class="name">${name}</span><span class="count">${count}</span></div>`
      ).join("");
}

function startClock() {
  const clockEl = document.getElementById("clock");
  setInterval(() => {
    clockEl.textContent = new Date().toTimeString().split(" ")[0];
  }, 1000);
}

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("login-form").addEventListener("submit", handleLogin);
  document.getElementById("logout-btn").addEventListener("click", handleLogout);

  const restored = await tryRestoreSession();
  if (!restored) {
    document.getElementById("login-screen").classList.remove("hidden");
  }
});
