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

// ---------------- alert storage + detail card ----------------

let _alertSeq = 0;
const alertsById = {};      // id -> full alert object, so a click can re-show it
const ipInfoCache = {};     // ip -> fetched info, avoids re-fetching on repeat clicks

function renderAlert(alert) {
  const feed = document.getElementById("feed");
  const empty = document.getElementById("feed-empty");
  if (empty) empty.remove();

  const id = _alertSeq++;
  alertsById[id] = alert;

  const row = document.createElement("div");
  row.className = "alert-row " + severityClass(alert.severity);
  row.dataset.alertId = id;
  row.innerHTML = `
    <span class="alert-time">${fmtTime(alert.timestamp)}</span>
    <span class="alert-sev">${alert.severity.toUpperCase()}</span>
    <span class="alert-msg">
      <span class="alert-type-tag">${alert.alert_type}</span>
      <span class="alert-src">${alert.src_ip}</span>
      <span class="alert-service-tag"></span><br>
      ${alert.message}
    </span>
  `;
  row.addEventListener("click", () => openDetailCard(alert));
  feed.prepend(row);
  annotateRowWithService(row, alert);

  // cap DOM growth — keep the most recent 200 rows rendered
  while (feed.children.length > 200) {
    feed.removeChild(feed.lastChild);
  }
}

function kvRow(key, value) {
  return `<div class="kv-row"><span class="k">${key}</span><span class="v">${value}</span></div>`;
}

function renderRawDetails(details) {
  const el = document.getElementById("detail-raw");
  const entries = Object.entries(details || {});
  if (entries.length === 0) {
    el.innerHTML = "&mdash;";
    return;
  }
  el.innerHTML = entries
    .map(([k, v]) => kvRow(k, Array.isArray(v) ? v.join(", ") : JSON.stringify(v).replace(/^"|"$/g, "")))
    .join("");
}

function renderIpInfo(info) {
  const el = document.getElementById("detail-ipinfo");

  if (info.is_private) {
    el.innerHTML = kvRow("scope", "private / local network")
      + `<span class="ip-tag private">LAN</span>`;
    return;
  }

  const rows = [];
  if (info.service) {
    rows.push(kvRow("service", `<span class="service-name">${info.service}</span>`));
  }
  rows.push(kvRow("hostname", info.hostname || "no PTR record"));
  rows.push(kvRow("organization", info.org || "unknown"));
  rows.push(kvRow("asn", info.asn || "unknown"));
  rows.push(kvRow("isp", info.isp || "unknown"));
  const location = [info.city, info.region, info.country].filter(Boolean).join(", ");
  rows.push(kvRow("location", location || "unknown"));

  el.innerHTML = rows.join("") + (info.cached ? `<span class="ip-tag">cached</span>` : "");
}

// Pure fetch-with-cache — used by both the detail card and the inline
// row service-tag annotation, so a repeat lookup for the same IP never
// hits the network (or the ip-api.com rate limit) twice.
function fetchIpInfoCached(ip) {
  if (ipInfoCache[ip]) {
    return Promise.resolve(ipInfoCache[ip]);
  }
  return fetch(`/api/ip-info/${encodeURIComponent(ip)}`)
    .then((r) => r.json())
    .then((info) => {
      ipInfoCache[ip] = info;
      return info;
    })
    .catch(() => null);
}

function fetchIpInfo(ip) {
  const el = document.getElementById("detail-ipinfo");

  if (ipInfoCache[ip]) {
    renderIpInfo(ipInfoCache[ip]);
    return;
  }

  el.innerHTML = '<span class="detail-loading">looking up&hellip;</span>';

  fetchIpInfoCached(ip).then((info) => {
    if (info) {
      renderIpInfo(info);
    } else {
      el.innerHTML = '<span class="detail-loading">lookup failed &mdash; offline or rate-limited</span>';
    }
  });
}

// Best-effort service-name tag shown directly on the alert feed row, so
// you don't have to click into every alert to see "oh, that's Google" —
// tries the alert's own src_ip first, and if that's a private/LAN address
// (the common case when YOU are the src, e.g. outbound SEQ/TTL alerts),
// falls back to the peer IP from the flow's session_key if present.
function annotateRowWithService(row, alert) {
  const candidates = [alert.src_ip];
  const sessionKey = alert.details && alert.details.session_key;
  if (Array.isArray(sessionKey) && sessionKey.length >= 3) {
    candidates.push(sessionKey[2]);
  }

  function tryNext(i) {
    if (i >= candidates.length) return;
    const ip = candidates[i];
    if (!ip) { tryNext(i + 1); return; }
    fetchIpInfoCached(ip).then((info) => {
      if (!info) { tryNext(i + 1); return; }
      if (info.service) {
        const tagEl = row.querySelector(".alert-service-tag");
        if (tagEl) tagEl.textContent = "· " + info.service;
      } else if (!info.is_private) {
        tryNext(i + 1);
      }
    });
  }
  tryNext(0);
}

function openDetailCard(alert) {
  document.getElementById("detail-type").textContent = alert.alert_type;

  const sevEl = document.getElementById("detail-sev");
  sevEl.textContent = alert.severity.toUpperCase();
  sevEl.className = "detail-sev " + severityClass(alert.severity);

  document.getElementById("detail-time").textContent = fmtTime(alert.timestamp);
  document.getElementById("detail-ip").textContent = alert.src_ip;
  document.getElementById("detail-message").textContent = alert.message;

  renderRawDetails(alert.details);
  fetchIpInfo(alert.src_ip);

  document.getElementById("detail-overlay").classList.remove("hidden");
}

function closeDetailCard() {
  document.getElementById("detail-overlay").classList.add("hidden");
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
  document.getElementById("detail-close").addEventListener("click", closeDetailCard);
  document.getElementById("detail-overlay").addEventListener("click", (e) => {
    if (e.target.id === "detail-overlay") closeDetailCard();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDetailCard();
  });

  typeBootSequence(() => {
    document.getElementById("boot-screen").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");
    startClock();
    connectSocket();
  });
});
