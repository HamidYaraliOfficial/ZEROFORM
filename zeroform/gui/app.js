/* ================================================================
   ZEROFORM Dashboard — application logic
   Vanilla JS, no build step. Talks to the ZEROFORM REST API
   (zeroform.api.server) when reachable; otherwise falls back to a
   clearly-labelled bundled demo compile so the interface is still
   fully explorable offline.
   ================================================================ */
(function () {
  "use strict";

  /* ---------------- state ---------------- */
  const STORAGE = {
    theme: "zeroform.theme",
    lang: "zeroform.lang",
    apiBase: "zeroform.apiBase",
    hours: "zeroform.hoursSchedule",
  };

  const state = {
    theme: localStorage.getItem(STORAGE.theme) || "windows",
    lang: localStorage.getItem(STORAGE.lang) || "en",
    apiBase: localStorage.getItem(STORAGE.apiBase) || "http://127.0.0.1:8000",
    connected: false,
    lastCompile: null,
    page: "overview",
    hoursTicker: null,
  };

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function t(key) {
    const dict = window.ZF_I18N[state.lang] || window.ZF_I18N.en;
    return dict[key] != null ? dict[key] : (window.ZF_I18N.en[key] || key);
  }

  /* ---------------- bundled sample world (kept in sync with
     zeroform/examples/sample_world.zf) so the GUI is explorable
     even with no backend running. ---------------- */
  const SAMPLE_WORLD = `world "Acme Payments Reality" {
  version: "0.1.0"
  description: "Minimal payments flow used to demonstrate the ZEROFORM pipeline"
}

trust_zone "Internet" { level: 0 }
trust_zone "Internal" { level: 5, parent: "Internet" }
trust_zone "Secure" { level: 8, parent: "Internal" }
trust_zone "Secrets" { level: 10, parent: "Secure" }

identity "user:alice" { type: "User", roles: ["Operator"], trust_zone: "Internet", criticality: "high" }
agent "agent:refund-bot" { type: "Agent", roles: ["ServiceAccount"], trust_zone: "Internal" }
api "api:payments-gateway" { type: "API", owner: "team-payments", trust_zone: "Internal", criticality: "high" }
database "db:payments" { type: "Database", trust_zone: "Secure", classification: "Restricted", owner: "team-payments" }
secret "secret:payments-db-password" { type: "Secret", trust_zone: "Secrets", owner: "team-payments" }
external_system "partner:card-network" { type: "ExternalSystem", trust_zone: "Internet" }

flow "alice-calls-gateway" { from: "user:alice", to: "api:payments-gateway", action: "calls", classification: "Confidential" }
flow "gateway-reads-db" { from: "api:payments-gateway", to: "db:payments", action: "reads", classification: "Restricted" }
flow "gateway-uses-secret" { from: "api:payments-gateway", to: "secret:payments-db-password", action: "uses", classification: "Secret" }
flow "gateway-calls-partner" { from: "api:payments-gateway", to: "partner:card-network", action: "calls", classification: "Confidential" }
flow "refundbot-reads-db" { from: "agent:refund-bot", to: "db:payments", action: "reads", classification: "Restricted" }
`;

  const DEMO_COMPILE_RESULT = {
    world_name: "Acme Payments Reality", version: "0.1.0",
    node_count: 11, edge_count: 17, boundary_crossings: 8, controls: 40,
    policies: [
      { policy_id: "policy_demo_json", target: "json", version: "1.0.0", signature: "demo" },
      { policy_id: "policy_demo_wasm", target: "wasm", version: "1.0.0", signature: "demo" },
    ],
    findings: [],
    source_model_hash: "demo-offline-hash",
    duration_seconds: 0.0021,
    _demo: true,
  };

  /* ---------------- API client ---------------- */
  async function api(path, options) {
    const url = state.apiBase.replace(/\/$/, "") + path;
    const res = await fetch(url, Object.assign({
      headers: { "Content-Type": "application/json" },
    }, options || {}));
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`${res.status} ${res.statusText}: ${body}`);
    }
    return res.json();
  }

  async function checkConnection() {
    const dot = $("#connDot"), label = $("#connLabel");
    label.textContent = t("connChecking");
    try {
      await api("/api/health");
      state.connected = true;
      dot.className = "conn-dot online";
      label.textContent = t("connOnline");
    } catch (e) {
      state.connected = false;
      dot.className = "conn-dot offline";
      label.textContent = t("connOffline");
    }
  }

  /* ---------------- theming / language ---------------- */
  function applyTheme(theme) {
    state.theme = theme;
    localStorage.setItem(STORAGE.theme, theme);
    document.documentElement.setAttribute("data-theme", theme);
    $$(".theme-swatch").forEach((el) => el.classList.toggle("selected", el.dataset.theme === theme));
  }

  function applyLang(lang) {
    state.lang = lang;
    localStorage.setItem(STORAGE.lang, lang);
    const dict = window.ZF_I18N[lang] || window.ZF_I18N.en;
    document.documentElement.setAttribute("lang", lang);
    document.documentElement.setAttribute("dir", dict.dir);
    $$(".lang-btn").forEach((el) => el.classList.toggle("active", el.dataset.lang === lang));
    renderStaticText();
    renderPage(state.page); // re-render dynamic content in new language
  }

  function renderStaticText() {
    $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    $$("[data-i18n-placeholder]").forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    document.title = `${t("appName")} — ${t("appTagline")}`;
  }

  /* ---------------- navigation ---------------- */
  function goToPage(page) {
    state.page = page;
    $$(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.page === page));
    $$(".page").forEach((el) => el.classList.toggle("hidden", el.id !== `page-${page}`));
    renderPage(page);
  }

  function renderPage(page) {
    if (page === "overview") renderOverview();
    if (page === "graph") renderGraph();
    if (page === "policies") renderPolicies();
    if (page === "hours") renderHours();
    if (page === "settings") renderSettings();
  }

  /* ---------------- Overview / compile ---------------- */
  function severityBadge(sev) {
    return `<span class="badge badge-${sev}">${sev}</span>`;
  }

  async function doCompile() {
    const src = $("#dslInput").value;
    const btn = $("#compileBtn");
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = t("compiling");
    try {
      let result;
      if (state.connected) {
        result = await api("/api/compile", { method: "POST", body: JSON.stringify({ source: src }) });
      } else {
        await new Promise((r) => setTimeout(r, 250));
        result = DEMO_COMPILE_RESULT;
      }
      state.lastCompile = result;
      renderOverview();
      renderGraph();
      renderPolicies();
    } catch (e) {
      state.lastCompile = { error: String(e) };
      renderOverview();
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  }

  function renderOverview() {
    const out = $("#compileOutput");
    if (!state.lastCompile) {
      out.innerHTML = "";
      return;
    }
    if (state.lastCompile.error) {
      out.innerHTML = `<div class="empty-state">${state.lastCompile.error}</div>`;
      return;
    }
    const r = state.lastCompile;
    const demoNote = r._demo
      ? `<div class="status-banner closed"><span class="status-dot"></span><span>${t("connOffline")}</span></div>` : "";
    out.innerHTML = `
      ${demoNote}
      <div class="stat-grid">
        <div class="stat-box"><div class="stat-value">${r.node_count}</div><div class="stat-label">${t("nodeCount")}</div></div>
        <div class="stat-box"><div class="stat-value">${r.edge_count}</div><div class="stat-label">${t("edgeCount")}</div></div>
        <div class="stat-box"><div class="stat-value">${r.boundary_crossings}</div><div class="stat-label">${t("crossingCount")}</div></div>
        <div class="stat-box"><div class="stat-value">${r.controls}</div><div class="stat-label">${t("controlCount")}</div></div>
        <div class="stat-box"><div class="stat-value">${r.policies.length}</div><div class="stat-label">${t("policyCount")}</div></div>
        <div class="stat-box"><div class="stat-value">${r.findings.length}</div><div class="stat-label">${t("findingCount")}</div></div>
      </div>
      <p class="card-subtitle" style="margin-top:12px;">${t("worldName")}: <strong>${r.world_name}</strong> ·
        ${t("worldVersion")}: <strong>${r.version}</strong> ·
        ${t("durationLabel")}: <strong>${(r.duration_seconds * 1000).toFixed(1)}ms</strong></p>`;
  }

  /* ---------------- Graph / findings ---------------- */
  function renderGraph() {
    const body = $("#findingsBody");
    const r = state.lastCompile;
    if (!r || r.error || !r.findings || r.findings.length === 0) {
      body.innerHTML = `<tr><td colspan="3"><div class="empty-state">${t("noFindings")}</div></td></tr>`;
      return;
    }
    body.innerHTML = r.findings.map((f) => `
      <tr>
        <td>${severityBadge(f.severity)}</td>
        <td>${f.kind}</td>
        <td>${f.description}</td>
      </tr>`).join("");
  }

  /* ---------------- Policies ---------------- */
  function renderPolicies() {
    const body = $("#policiesBody");
    const r = state.lastCompile;
    if (!r || r.error || !r.policies || r.policies.length === 0) {
      body.innerHTML = `<tr><td colspan="4"><div class="empty-state">—</div></td></tr>`;
      return;
    }
    body.innerHTML = r.policies.map((p) => {
      const signed = p._demo || p.signature ? "yes" : "no";
      return `<tr>
        <td><code>${p.policy_id}</code></td>
        <td>${p.target}</td>
        <td>${p.version}</td>
        <td><span class="pill ${signed === 'yes' ? 'pill-ok' : 'pill-bad'}">${signed === 'yes' ? t('signedYes') : t('signedNo')}</span></td>
      </tr>`;
    }).join("");
  }

  /* ---------------- Scenario Lab ---------------- */
  async function runScenario() {
    const out = $("#scenarioOutput");
    const nameInput = $("#scenarioName").value || "ad_hoc";
    let events = [];
    try {
      events = JSON.parse($("#scenarioEvents").value || "[]");
    } catch (e) {
      out.innerHTML = `<div class="empty-state">${e}</div>`;
      return;
    }
    if (!state.connected) {
      out.innerHTML = `<div class="status-banner closed"><span class="status-dot"></span><span>${t("connOffline")}</span></div>`;
      return;
    }
    try {
      const result = await api("/api/scenario/run", {
        method: "POST",
        body: JSON.stringify({ source: $("#dslInput").value || SAMPLE_WORLD, scenario_name: nameInput, events }),
      });
      const statusClass = result.passed ? "open" : "closed";
      const statusText = result.passed ? t("scenarioPassed") : t("scenarioFailed");
      const violations = result.violations.map((v) => `<li>${v}</li>`).join("");
      const timeline = result.timeline.map((entry) => `
        <div class="timeline-item"><span class="timeline-step">#${entry.step}</span><span>[${entry.kind}] ${JSON.stringify(entry.detail)}</span></div>
      `).join("");
      out.innerHTML = `
        <div class="status-banner ${statusClass}"><span class="status-dot"></span><span>${statusText}</span></div>
        ${violations ? `<ul>${violations}</ul>` : ""}
        <div class="timeline-list">${timeline}</div>`;
    } catch (e) {
      out.innerHTML = `<div class="empty-state">${e}</div>`;
    }
  }

  /* ---------------- Refactor Advisor ---------------- */
  async function runRefactor() {
    const out = $("#refactorOutput");
    if (!state.connected) {
      out.innerHTML = `<div class="status-banner closed"><span class="status-dot"></span><span>${t("connOffline")}</span></div>`;
      return;
    }
    try {
      const proposals = await api("/api/refactor", {
        method: "POST",
        body: JSON.stringify({ source: $("#dslInput").value || SAMPLE_WORLD }),
      });
      if (!proposals.length) {
        out.innerHTML = `<div class="empty-state">${t("refactorNone")}</div>`;
        return;
      }
      out.innerHTML = proposals.map((p) => `
        <div class="card" style="margin-top:0;">
          <div class="card-title">${p.title}</div>
          <p><strong>${t("refactorBenefit")}:</strong> ${p.security_benefit}</p>
          <p><strong>${t("refactorImpact")}:</strong> ${p.functional_impact}</p>
          <p><strong>${t("refactorCost")}:</strong> ${p.operational_cost}</p>
        </div>`).join("");
    } catch (e) {
      out.innerHTML = `<div class="empty-state">${e}</div>`;
    }
  }

  /* ---------------- Release Passport ---------------- */
  async function buildReport() {
    const out = $("#reportOutput");
    if (!state.connected) {
      out.innerHTML = `<div class="status-banner closed"><span class="status-dot"></span><span>${t("connOffline")}</span></div>`;
      return;
    }
    try {
      const result = await api("/api/report", {
        method: "POST",
        body: JSON.stringify({ source: $("#dslInput").value || SAMPLE_WORLD }),
      });
      const p = result.passport;
      out.innerHTML = `
        <div class="stat-grid">
          <div class="stat-box"><div class="stat-value">${p.controls_generated}</div><div class="stat-label">${t("controlCount")}</div></div>
          <div class="stat-box"><div class="stat-value">${p.verification_tests_passed}</div><div class="stat-label">Verified</div></div>
          <div class="stat-box"><div class="stat-value">${p.open_findings}</div><div class="stat-label">${t("findingCount")}</div></div>
          <div class="stat-box"><div class="stat-value" style="text-transform:capitalize">${p.residual_risk}</div><div class="stat-label">${t("residualRisk")}</div></div>
        </div>
        <div class="markdown-preview" style="margin-top:14px;">${result.documentation_markdown.replace(/[<>&]/g, (c) => ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]))}</div>`;
    } catch (e) {
      out.innerHTML = `<div class="empty-state">${e}</div>`;
    }
  }

  /* ================================================================
     Operating Hours panel — every value is user-entered. Mirrors
     zeroform.core.availability.OperatingHoursEngine in JS so the
     status banner can tick live client-side; if the backend is
     reachable the schedule is also persisted there via PUT
     /api/hours/schedule.
     ================================================================ */
  function defaultSchedule() {
    const days = {};
    for (let wd = 0; wd < 7; wd++) {
      days[wd] = { weekday: wd, closed: wd >= 5, is_24h: false,
                   windows: wd >= 5 ? [] : [{ open_time: "09:00", close_time: "18:00" }] };
    }
    return { timezone_label: "UTC", days, exceptions: [] };
  }

  function loadHoursSchedule() {
    try {
      const raw = localStorage.getItem(STORAGE.hours);
      if (raw) return JSON.parse(raw);
    } catch (e) { /* ignore corrupt storage */ }
    return defaultSchedule();
  }

  function saveHoursScheduleLocal(schedule) {
    localStorage.setItem(STORAGE.hours, JSON.stringify(schedule));
  }

  function parseHHMM(v) {
    const [h, m] = v.split(":").map(Number);
    return h * 60 + m;
  }

  function fmtDuration(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    const days = Math.floor(seconds / 86400); seconds %= 86400;
    const hours = Math.floor(seconds / 3600); seconds %= 3600;
    const minutes = Math.floor(seconds / 60); seconds %= 60;
    const parts = [];
    if (days) parts.push(`${days}d`);
    if (hours || days) parts.push(`${hours}h`);
    if (minutes || hours || days) parts.push(`${minutes}m`);
    parts.push(`${seconds}s`);
    return parts.join(" ");
  }

  function dayWindowsAsDates(dateObj, daySchedule, exception) {
    const effective = exception || daySchedule;
    if (effective.closed) return [];
    if (effective.is_24h) {
      const start = new Date(dateObj); start.setHours(0, 0, 0, 0);
      const end = new Date(start); end.setDate(end.getDate() + 1);
      return [{ start, end }];
    }
    const windows = effective.windows || [];
    return windows.map((w) => {
      const start = new Date(dateObj); start.setHours(0, 0, 0, 0);
      const openMin = parseHHMM(w.open_time), closeMin = parseHHMM(w.close_time);
      start.setMinutes(openMin);
      const end = new Date(dateObj); end.setHours(0, 0, 0, 0); end.setMinutes(closeMin);
      if (closeMin <= openMin) end.setDate(end.getDate() + 1);
      return { start, end };
    });
  }

  function computeHoursStatus(schedule, now) {
    now = now || new Date();
    const exceptionFor = (d) => {
      const key = d.toISOString().slice(0, 10);
      return (schedule.exceptions || []).find((e) => e.on_date === key) || null;
    };
    let windows = [];
    for (let offset = -1; offset <= 15; offset++) {
      const day = new Date(now); day.setDate(day.getDate() + offset);
      const wd = (day.getDay() + 6) % 7; // JS: 0=Sun -> convert to 0=Mon
      const daySchedule = schedule.days[wd] || schedule.days[String(wd)];
      windows = windows.concat(dayWindowsAsDates(day, daySchedule, exceptionFor(day)));
    }
    windows.sort((a, b) => a.start - b.start);

    for (const w of windows) {
      if (w.start <= now && now < w.end) {
        return {
          is_open: true,
          seconds_until_close: (w.end - now) / 1000,
          current_window_closes_at: w.end,
        };
      }
    }
    const future = windows.filter((w) => w.start > now);
    if (!future.length) return { is_open: false, no_upcoming: true };
    return { is_open: false, seconds_until_open: (future[0].start - now) / 1000, next_open_at: future[0].start };
  }

  let currentSchedule = loadHoursSchedule();

  function renderHours() {
    currentSchedule = loadHoursSchedule();
    const grid = $("#hoursGrid");
    const weekdayKeys = ["weekday0", "weekday1", "weekday2", "weekday3", "weekday4", "weekday5", "weekday6"];
    grid.innerHTML = weekdayKeys.map((key, wd) => {
      const d = currentSchedule.days[wd] || currentSchedule.days[String(wd)];
      const w = (d.windows && d.windows[0]) || { open_time: "09:00", close_time: "18:00" };
      return `
        <div class="hours-row" data-wd="${wd}">
          <div class="day-name">${t(key)}</div>
          <label class="checkbox-field"><input type="checkbox" class="hrs-closed" ${d.closed ? "checked" : ""}/> ${t("hoursClosed")}</label>
          <label class="checkbox-field"><input type="checkbox" class="hrs-24h" ${d.is_24h ? "checked" : ""}/> ${t("hoursOpen24")}</label>
          <div><label>${t("hoursFrom")}</label><input type="time" class="hrs-open" value="${w.open_time}" ${d.closed || d.is_24h ? "disabled" : ""}/></div>
          <div><label>${t("hoursTo")}</label><input type="time" class="hrs-close" value="${w.close_time}" ${d.closed || d.is_24h ? "disabled" : ""}/></div>
        </div>`;
    }).join("");

    $("#hoursTimezone").value = currentSchedule.timezone_label || "UTC";
    renderExceptions();
    tickHoursStatus();
    if (state.hoursTicker) clearInterval(state.hoursTicker);
    state.hoursTicker = setInterval(tickHoursStatus, 1000);

    grid.onchange = (e) => {
      const row = e.target.closest(".hours-row");
      if (!row) return;
      const openInput = row.querySelector(".hrs-open");
      const closeInput = row.querySelector(".hrs-close");
      const closed = row.querySelector(".hrs-closed").checked;
      const is24h = row.querySelector(".hrs-24h").checked;
      openInput.disabled = closed || is24h;
      closeInput.disabled = closed || is24h;
    };
  }

  function renderExceptions() {
    const list = $("#hoursExceptionsList");
    const items = currentSchedule.exceptions || [];
    if (!items.length) {
      list.innerHTML = `<div class="empty-state">—</div>`;
      return;
    }
    list.innerHTML = items.map((e, i) => `
      <div class="hours-row" style="grid-template-columns: 1fr 1fr auto;">
        <div>${e.on_date}</div>
        <div>${e.label || t("hoursClosed")}</div>
        <button class="btn btn-secondary" data-remove-exc="${i}">✕</button>
      </div>`).join("");
    $$("[data-remove-exc]", list).forEach((btn) => {
      btn.onclick = () => {
        currentSchedule.exceptions.splice(Number(btn.dataset.removeExc), 1);
        saveHoursScheduleLocal(currentSchedule);
        renderExceptions();
        tickHoursStatus();
      };
    });
  }

  function tickHoursStatus() {
    const banner = $("#hoursStatusBanner");
    if (!banner) return;
    const status = computeHoursStatus(currentSchedule, new Date());
    if (status.is_open) {
      banner.className = "status-banner open";
      banner.innerHTML = `<span class="status-dot"></span>
        <span>${t("hoursStatusOpen")}</span>
        <span class="status-sub">${t("hoursClosesIn")}: ${fmtDuration(status.seconds_until_close)}</span>`;
    } else if (status.no_upcoming) {
      banner.className = "status-banner closed";
      banner.innerHTML = `<span class="status-dot"></span><span>${t("hoursStatusClosed")}</span>
        <span class="status-sub">${t("hoursNoUpcoming")}</span>`;
    } else {
      banner.className = "status-banner closed";
      banner.innerHTML = `<span class="status-dot"></span>
        <span>${t("hoursStatusClosed")}</span>
        <span class="status-sub">${t("hoursOpensIn")}: ${fmtDuration(status.seconds_until_open)}</span>`;
    }
  }

  async function saveHoursSchedule() {
    const rows = $$(".hours-row[data-wd]");
    const days = {};
    rows.forEach((row) => {
      const wd = row.dataset.wd;
      const closed = row.querySelector(".hrs-closed").checked;
      const is24h = row.querySelector(".hrs-24h").checked;
      const openT = row.querySelector(".hrs-open").value || "09:00";
      const closeT = row.querySelector(".hrs-close").value || "18:00";
      days[wd] = { weekday: Number(wd), closed, is_24h: is24h,
                   windows: closed || is24h ? [] : [{ open_time: openT, close_time: closeT }] };
    });
    currentSchedule = { timezone_label: $("#hoursTimezone").value || "UTC", days, exceptions: currentSchedule.exceptions || [] };
    saveHoursScheduleLocal(currentSchedule);
    tickHoursStatus();
    if (state.connected) {
      try { await api("/api/hours/schedule", { method: "PUT", body: JSON.stringify(currentSchedule) }); }
      catch (e) { /* local save still succeeded */ }
    }
  }

  function addHoursException() {
    const date = $("#hoursExcDate").value;
    const label = $("#hoursExcLabel").value;
    if (!date) return;
    currentSchedule.exceptions = currentSchedule.exceptions || [];
    currentSchedule.exceptions.push({ on_date: date, closed: true, is_24h: false, windows: [], label });
    saveHoursScheduleLocal(currentSchedule);
    $("#hoursExcDate").value = "";
    $("#hoursExcLabel").value = "";
    renderExceptions();
    tickHoursStatus();
  }

  /* ---------------- Settings ---------------- */
  function renderSettings() {
    $("#apiBaseInput").value = state.apiBase;
  }

  /* ---------------- wiring ---------------- */
  function wireEvents() {
    $$(".nav-item").forEach((el) => el.addEventListener("click", () => goToPage(el.dataset.page)));
    $$(".theme-swatch").forEach((el) => el.addEventListener("click", () => applyTheme(el.dataset.theme)));
    $$(".lang-btn").forEach((el) => el.addEventListener("click", () => applyLang(el.dataset.lang)));

    $("#loadSampleBtn").addEventListener("click", () => { $("#dslInput").value = SAMPLE_WORLD; });
    $("#compileBtn").addEventListener("click", doCompile);
    $("#scenarioRunBtn").addEventListener("click", runScenario);
    $("#refactorRunBtn").addEventListener("click", runRefactor);
    $("#reportBuildBtn").addEventListener("click", buildReport);
    $("#hoursSaveBtn").addEventListener("click", saveHoursSchedule);
    $("#hoursExcAddBtn").addEventListener("click", addHoursException);
    $("#connCheckBtn").addEventListener("click", checkConnection);
    $("#apiBaseInput").addEventListener("change", (e) => {
      state.apiBase = e.target.value.trim() || "http://127.0.0.1:8000";
      localStorage.setItem(STORAGE.apiBase, state.apiBase);
      checkConnection();
    });
  }

  /* ---------------- boot ---------------- */
  function boot() {
    applyTheme(state.theme);
    applyLang(state.lang);
    $("#dslInput").value = SAMPLE_WORLD;
    wireEvents();
    goToPage("overview");
    checkConnection();
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
