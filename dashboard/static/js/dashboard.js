// dashboard.js — SENTINEL live dashboard
// Boot sequence is cosmetic framing; everything after it is driven by
// real SocketIO events pushed from main.py (init_state, new_alert, stats_update).

const BOOT_LINES = [
  "SENTINEL v0.1 — session hijack & network scan detector",
  "loading detection modules...",
  "  [ok] scan_detector   (port scan / SYN flood / open port)",
  "  [ok] hijack_detector (ttl / seq / mac / rst / dup-ack)",
  "  [ok] alert_manager",
  `mode: ${(window.__SENTINEL_MODE__ || "unknown").toUpperCase()}`,
  `interface: ${window.__SENTINEL_IFACE__ || "n/a"}`,
  "connecting to event stream...",
];

function typeBootSequence(onDone) {
  const el = document.getElementById("boot-text");
  let i = 0;
  let text = "";

  function nextLine() {
    if (i >= BOOT_LINES.length) {
      el.innerHTML = text + '<span class="cursor">&nbsp;</span>';
      setTimeout(onDone, 450);
      return;
    }
    text += (i > 0 ? "\n" : "") + "> " + BOOT_LINES[i];
    el.textContent = text;
    i += 1;
    setTimeout(nextLine, 140);
  }
  nextLine();
}

function severityClass(sev) {
  return "sev-" + sev;
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return d.toTimeString().split(" ")[0];
}

function renderAlert(alert) {
  const feed = document.getElementById("feed");
  const empty = document.getElementById("feed-empty");
  if (empty) empty.remove();

  const row = document.createElement("div");
  row.className = "alert-row " + severityClass(alert.severity);
  row.innerHTML = `
    <span class="alert-time">${fmtTime(alert.timestamp)}</span>
    <span class="alert-sev">${alert.severity.toUpperCase()}</span>
    <span class="alert-msg">
      <span class="alert-type-tag">${alert.alert_type}</span>
      <span class="alert-src">${alert.src_ip}</span><br>
      ${alert.message}
    </span>
  `;
  feed.prepend(row);

  // cap DOM growth — keep the most recent 200 rows rendered
  while (feed.children.length > 200) {
    feed.removeChild(feed.lastChild);
  }
}

function renderStats(stats) {
  const total = stats.total || 0;
  document.getElementById("feed-count").textContent = `${total} event${total === 1 ? "" : "s"}`;

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
  const byType = stats.by_type || {};
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    typeList.innerHTML = '<div class="type-empty">&mdash;</div>';
  } else {
    typeList.innerHTML = entries
      .map(([name, count]) => `
        <div class="type-row">
          <span class="name">${name}</span>
          <span class="count">${count}</span>
        </div>`)
      .join("");
  }
}

function startClock() {
  const clockEl = document.getElementById("clock");
  const startTime = Date.now();
  const uptimeEl = document.getElementById("uptime");

  setInterval(() => {
    const now = new Date();
    clockEl.textContent = now.toTimeString().split(" ")[0];

    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const h = String(Math.floor(elapsed / 3600)).padStart(2, "0");
    const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, "0");
    const s = String(elapsed % 60).padStart(2, "0");
    uptimeEl.textContent = `${h}:${m}:${s}`;
  }, 1000);
}

function connectSocket() {
  const socket = io();

  socket.on("connect", () => {
    document.getElementById("live-dot").style.background = "var(--signal)";
  });

  socket.on("disconnect", () => {
    document.getElementById("live-dot").style.background = "var(--critical)";
  });

  socket.on("init_state", (data) => {
    (data.recent_alerts || []).slice().reverse().forEach(renderAlert);
    renderStats(data.stats || {});
    if (data.session_count !== undefined) {
      document.getElementById("session-count").textContent = data.session_count;
    }
  });

  socket.on("new_alert", (alert) => {
    renderAlert(alert);
  });

  socket.on("stats_update", (data) => {
    renderStats(data.stats || {});
    if (data.session_count !== undefined) {
      document.getElementById("session-count").textContent = data.session_count;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  typeBootSequence(() => {
    document.getElementById("boot-screen").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");
    startClock();
    connectSocket();
  });
});
