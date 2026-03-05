const $ = (sel) => document.querySelector(sel);

const rowsEl = $("#rows");
const detailCard = $("#detailCard");
const noteEl = $("#note");
const lastUpdate = $("#lastUpdate");
const liveDot = $("#liveDot");
const resultCount = $("#resultCount");
const currentMode = $("#currentMode");

const statTotal = $("#statTotal");
const statSystem = $("#statSystem");
const statApps = $("#statApps");
const statSuspicious = $("#statSuspicious");
const statSuspiciousMeta = $("#statSuspiciousMeta");

const searchEl = $("#search");
const categoryEl = $("#category");
const sortEl = $("#sort");
const intervalEl = $("#interval");
const intervalLabel = $("#intervalLabel");
const limitEl = $("#limit");

const btnPause = $("#pause");
const btnRefresh = $("#refresh");
const adminTokenEl = $("#adminToken");
const btnExportJson = $("#btnExportJson");
const btnExportCsv = $("#btnExportCsv");
const btnDiff = $("#btnDiff");
const btnAudit = $("#btnAudit");
const btnEbpf = $("#btnEbpf");

let timer = null;
let paused = false;
let selectedPid = null;
let currentItems = [];

let adminToken = localStorage.getItem("procwatch_admin_token") || "";
let configCache = null;

function fmtTime(ts) {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

function badgeClass(cat) {
  if (cat === "system") return "badge badge-system";
  if (cat === "apps") return "badge badge-apps";
  if (cat === "commands") return "badge badge-commands";
  return "badge badge-suspicious";
}

function catLabel(cat) {
  if (cat === "system") return "Système";
  if (cat === "apps") return "Application";
  if (cat === "commands") return "Commande";
  return "Suspect";
}

function sortLabel(value) {
  if (value === "mem") return "RAM";
  if (value === "pid") return "PID";
  if (value === "name") return "Nom";
  return "CPU";
}

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[c]));
}

function setNotice(html, asHtml = false) {
  if (!noteEl) return;
  if (asHtml) noteEl.innerHTML = html;
  else noteEl.textContent = html;
}

function setAdminToken(value) {
  adminToken = value || "";
  try { localStorage.setItem("procwatch_admin_token", adminToken); } catch (e) {}
}

function adminHeaders() {
  const h = {};
  if (adminToken) h["X-Admin-Token"] = adminToken;
  return h;
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...adminHeaders() },
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.message || "request_failed");
  return data;
}

function fmtEpoch(ts) {
  if (!ts) return "–";
  try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return String(ts); }
}


function pulseLive() {
  anime({
    targets: liveDot,
    scale: [1, 1.28, 1],
    opacity: [1, 0.72, 1],
    duration: 650,
    easing: "easeInOutSine",
  });
}

function setPausedUI() {
  btnPause.textContent = paused ? "Reprendre" : "Pause";
  liveDot.style.opacity = paused ? "0.45" : "1";
  liveDot.style.boxShadow = paused ? "none" : "0 0 18px rgba(34, 197, 94, 0.7)";
}

function schedule() {
  clearInterval(timer);
  const ms = parseInt(intervalEl.value, 10);
  timer = setInterval(() => {
    if (!paused) load();
  }, ms);
}

function updateStats(items) {
  const counts = {
    total: items.length,
    system: 0,
    apps: 0,
    commands: 0,
    suspicious: 0,
  };

  for (const item of items) {
    if (counts[item.category] !== undefined) counts[item.category] += 1;
  }

  statTotal.textContent = counts.total;
  statSystem.textContent = counts.system;
  statApps.textContent = counts.apps;
  statSuspicious.textContent = counts.suspicious;
  statSuspiciousMeta.textContent = counts.suspicious > 0
    ? `${counts.commands} commande(s), ${counts.suspicious} alerte(s) heuristiques`
    : `${counts.commands} commande(s), aucune alerte visible`;

  resultCount.textContent = counts.total;
  currentMode.textContent = sortLabel(sortEl.value);
}

function detailTemplate(item) {
  const signals = (item.signals && item.signals.length) ? item.signals : (item.reasons || []);
  const allowlisted = item.allowlisted ? true : false;

  const signalsBox = signals.length
    ? `
      <div class="detail-box">
        <div class="detail-box-label">Signaux détectés</div>
        <ul class="detail-box-value list-disc pl-5 space-y-1 ${item.category === "suspicious" ? "text-red-100" : "text-slate-200"}">
          ${signals.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
        </ul>
      </div>
    `
    : `
      <div class="detail-box">
        <div class="detail-box-label">Signaux détectés</div>
        <div class="detail-box-value">Aucun signal détecté par les heuristiques locales.</div>
      </div>
    `;

  const sha = item.sha256 ? item.sha256 : "–";
  const dpkgOwner = item.dpkg_owner ? item.dpkg_owner : "–";
  const scriptPath = item.script_path ? item.script_path : "–";

  const baselineExec = item.baseline && item.baseline.exec ? item.baseline.exec : null;
  const baselineCmd = item.baseline && item.baseline.cmd ? item.baseline.cmd : null;

  const baselineBox = `
    <div class="detail-box">
      <div class="detail-box-label">Baseline</div>
      <div class="detail-box-value">
        <div>Hash exécutable: <span class="mono">${baselineExec ? (baselineExec.known ? "connu" : "nouveau") : "–"}</span></div>
        <div>Première vue: <span class="mono">${baselineExec && baselineExec.first_seen ? escapeHtml(fmtEpoch(baselineExec.first_seen)) : "–"}</span></div>
        <div>Occurrences: <span class="mono">${baselineExec && baselineExec.times_seen ? baselineExec.times_seen : "–"}</span></div>
        <div>Commande: <span class="mono">${baselineCmd ? (baselineCmd.known ? "connue" : "nouvelle") : "–"}</span></div>
      </div>
    </div>
  `;

  const allowBox = `
    <div class="detail-box">
      <div class="detail-box-label">Allowlist</div>
      <div class="detail-box-value">${allowlisted ? `Actif (${escapeHtml(item.allowlist_reason || "match")})` : "Non"}</div>
    </div>
  `;

  const networkMeta = item.network_meta || null;
  const networkMetaBox = networkMeta && Object.keys(networkMeta).length
    ? `
      <div class="detail-box">
        <div class="detail-box-label">Réseau (résumé)</div>
        <div class="detail-box-value mono">
          total=${networkMeta.count ?? "–"} · established=${networkMeta.established ?? "–"} · public=${networkMeta.remote_public ?? "–"} · private=${networkMeta.remote_private ?? "–"} · ports_suspects=${networkMeta.suspicious_ports ?? "–"} · ip_uniques=${networkMeta.unique_remote_ips ?? "–"}
        </div>
      </div>
    `
    : `
      <div class="detail-box">
        <div class="detail-box-label">Réseau (résumé)</div>
        <div class="detail-box-value">–</div>
      </div>
    `;

  const chain = item.parent_chain && item.parent_chain.length
    ? `
      <div class="detail-box">
        <div class="detail-box-label">Chaîne parent</div>
        <ul class="detail-box-value list-disc pl-5 space-y-1 text-slate-200">
          ${item.parent_chain.map((p) => `<li class="mono">${escapeHtml(p.name || "?")} (PID ${p.pid}) · ${escapeHtml((p.exe || "").split(" ").slice(0,1).join(" "))}</li>`).join("")}
        </ul>
      </div>
    `
    : `
      <div class="detail-box">
        <div class="detail-box-label">Chaîne parent</div>
        <div class="detail-box-value">–</div>
      </div>
    `;

  const connections = item.connections && item.connections.length
    ? `
      <div class="detail-box">
        <div class="detail-box-label">Connexions réseau</div>
        <ul class="detail-box-value list-disc pl-5 space-y-1 text-slate-200">
          ${item.connections.map((c) => {
            const left = c.laddr ? escapeHtml(c.laddr) : "–";
            const right = c.raddr ? escapeHtml(c.raddr) : "–";
            const st = c.status ? ` (${escapeHtml(c.status)})` : "";
            return `<li class="mono">${left} → ${right}${st}</li>`;
          }).join("")}
        </ul>
      </div>
    `
    : `
      <div class="detail-box">
        <div class="detail-box-label">Connexions réseau</div>
        <div class="detail-box-value">Aucune connexion (ou accès refusé).</div>
      </div>
    `;

  const openFiles = item.open_files && item.open_files.length
    ? `
      <div class="detail-box">
        <div class="detail-box-label">Fichiers ouverts</div>
        <ul class="detail-box-value list-disc pl-5 space-y-1 text-slate-200">
          ${item.open_files.map((p) => `<li class="mono">${escapeHtml(p)}</li>`).join("")}
        </ul>
      </div>
    `
    : `
      <div class="detail-box">
        <div class="detail-box-label">Fichiers ouverts</div>
        <div class="detail-box-value">–</div>
      </div>
    `;

  const yaraBox = item.yara && (item.yara.available || item.yara.error)
    ? `
      <div class="detail-box">
        <div class="detail-box-label">YARA</div>
        <div class="detail-box-value">
          ${item.yara.available ? "" : "Non disponible. "}
          ${item.yara.error ? `<div class="mono text-slate-300">${escapeHtml(item.yara.error)}</div>` : ""}
          ${item.yara.matches && item.yara.matches.length
            ? `<ul class="mt-2 list-disc pl-5 space-y-1 text-slate-200">
                ${item.yara.matches.map((m) => `<li class="mono">${escapeHtml(m.rule)} ${m.tags && m.tags.length ? `[${escapeHtml(m.tags.join(","))}]` : ""}</li>`).join("")}
              </ul>`
            : `<div class="mt-2 text-slate-300">Aucun match.</div>`
          }
        </div>
      </div>
    `
    : "";

  const parent = item.parent && item.parent.pid
    ? `${item.parent.name || "?"} (PID ${item.parent.pid})`
    : (item.ppid ? `PID ${item.ppid}` : "–");

  const cwdBox = `
    <div class="detail-box">
      <div class="detail-box-label">Répertoire de travail</div>
      <div class="detail-box-value mono">${escapeHtml(item.cwd || "–")}</div>
    </div>
  `;

  const hashBox = `
    <div class="detail-box">
      <div class="detail-box-label">SHA256 (exécutable)</div>
      <div class="detail-box-value mono">${escapeHtml(sha)}</div>
    </div>
  `;

  const dpkgBox = `
    <div class="detail-box">
      <div class="detail-box-label">Propriétaire dpkg</div>
      <div class="detail-box-value mono">${escapeHtml(dpkgOwner)}</div>
    </div>
  `;

  const scriptBox = `
    <div class="detail-box">
      <div class="detail-box-label">Script (si applicable)</div>
      <div class="detail-box-value mono">${escapeHtml(scriptPath)}</div>
    </div>
  `;

  const parentBox = `
    <div class="detail-box">
      <div class="detail-box-label">Parent direct</div>
      <div class="detail-box-value mono">${escapeHtml(parent)}</div>
    </div>
  `;

  const actionsBar = `
    <div class="detail-actions">
      <button class="btn btn-ghost" data-pw-action="yara">YARA</button>
      <button class="btn btn-ghost" data-pw-action="allowlist">Allowlist</button>
      <button class="btn btn-ghost" data-pw-action="suspend">Suspendre</button>
      <button class="btn btn-ghost" data-pw-action="resume">Reprendre</button>
      <button class="btn btn-ghost" data-pw-action="kill">Kill</button>
      <div class="renice-wrap">
        <input class="input input-sm" id="pwNice" type="number" min="-20" max="19" value="10" />
        <button class="btn btn-ghost" data-pw-action="renice">Renice</button>
      </div>
    </div>
  `;

  return `
    <div class="detail-top">
      <div>
        <div class="detail-title">${escapeHtml(item.name)}</div>
        <div class="mt-2 text-sm text-slate-300">PID <span class="mono text-slate-100">${item.pid}</span> · utilisateur <span class="mono text-slate-100">${escapeHtml(item.user)}</span></div>
        <div class="mt-1 text-xs text-slate-400">Token admin: ${adminToken ? "chargé" : "non défini"} · Allowlist: ${allowlisted ? "oui" : "non"}</div>
      </div>
      <div class="${badgeClass(item.category)}">${catLabel(item.category)}</div>
    </div>

    ${actionsBar}

    <div class="metric-grid">
      <div class="metric">
        <div class="metric-label">CPU</div>
        <div class="metric-value">${item.cpu}%</div>
      </div>
      <div class="metric">
        <div class="metric-label">RAM</div>
        <div class="metric-value">${item.mem}%</div>
      </div>
      <div class="metric">
        <div class="metric-label">Statut</div>
        <div class="metric-value">${escapeHtml(item.status)}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Démarré</div>
        <div class="metric-value text-sm">${escapeHtml(fmtTime(item.started))}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Risque</div>
        <div class="metric-value">${(item.risk_score ?? "–")}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Niveau</div>
        <div class="metric-value">${escapeHtml(item.risk_level ?? "–")}</div>
      </div>
    </div>

    <div class="detail-grid">
      <div class="detail-box">
        <div class="detail-box-label">Commande</div>
        <div class="detail-box-value mono">${escapeHtml(item.cmd || "–")}</div>
      </div>
      <div class="detail-box">
        <div class="detail-box-label">Exécutable</div>
        <div class="detail-box-value mono">${escapeHtml(item.exe || "–")}</div>
      </div>
      <div class="detail-box">
        <div class="detail-box-label">Terminal</div>
        <div class="detail-box-value mono">${escapeHtml(item.terminal || "–")}</div>
      </div>
      ${parentBox}
      ${cwdBox}
      ${hashBox}
      ${dpkgBox}
      ${scriptBox}
      ${baselineBox}
      ${allowBox}
      ${networkMetaBox}
      ${chain}
      ${signalsBox}
      ${connections}
      ${openFiles}
      ${yaraBox}
    </div>
  `;
}

function rowTemplate(item) {
  const pathLabel = item.category === "suspicious"
    ? (item.reasons && item.reasons.length ? item.reasons[0] : "Signal(s) détecté(s)")
    : (item.exe || item.cmd || "–");

  return `
    <div class="row" data-pid="${item.pid}">
      <div class="mono text-slate-200">${item.pid}</div>
      <div class="row-name">
        <strong class="truncate">${escapeHtml(item.name)}</strong>
        <span class="row-subline truncate">${escapeHtml(item.terminal || item.cmd || "Aucun terminal")}</span>
      </div>
      <div class="mono truncate text-slate-300">${escapeHtml(item.user)}</div>
      <div class="mono text-slate-200">${item.cpu}</div>
      <div class="mono text-slate-200">${item.mem}</div>
      <div class="${badgeClass(item.category)}">${catLabel(item.category)}</div>
      <div class="truncate text-slate-300">${escapeHtml(item.status)}</div>
      <div class="row-path truncate mono">${escapeHtml(pathLabel)}</div>
    </div>
  `;
}

function animateRowsIn(container) {
  gsap.fromTo(
    container.children,
    { opacity: 0, y: 10 },
    { opacity: 1, y: 0, duration: 0.24, stagger: 0.008, ease: "power2.out" }
  );
}

function showDetails(item) {
  detailCard.innerHTML = detailTemplate(item);
  wireDetailActions(item);
  gsap.fromTo(detailCard, { opacity: 0, y: 12 }, { opacity: 1, y: 0, duration: 0.28, ease: "power2.out" });
}

async function loadDetails(pid, opts = {}) {
  try {
    const qs = opts && opts.yara ? "?yara=1" : "";
    const res = await fetch(`/api/process/${pid}${qs}`);
    if (!res.ok) return;
    const data = await res.json();
    // si l'utilisateur a déjà changé de sélection entre temps
    if (selectedPid !== pid) return;
    showDetails(data);
  } catch (e) {
    // ignore
  }
}


function wireDetailActions(item) {
  const root = detailCard;
  if (!root || !item || !item.pid) return;

  root.querySelectorAll("[data-pw-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.getAttribute("data-pw-action");
      const pid = item.pid;

      try {
        if (action === "yara") {
          setNotice("Scan YARA demandé…");
          await loadDetails(pid, { yara: true });
          setNotice("Scan YARA terminé.");
          return;
        }

        if (!adminToken) {
          setNotice("Action refusée: admin token non défini.");
          return;
        }

        if (action === "allowlist") {
          const payload = {
            sha256: item.sha256 ? [item.sha256] : [],
            paths: item.exe ? [item.exe] : [],
            names: item.name ? [item.name] : [],
          };
          await postJson("/api/allowlist/add", payload);
          setNotice("Allowlist mise à jour.");
          await loadDetails(pid);
          return;
        }

        if (action === "suspend") {
          await postJson("/api/action/suspend", { pid });
          setNotice("Processus suspendu.");
          await loadDetails(pid);
          return;
        }

        if (action === "resume") {
          await postJson("/api/action/resume", { pid });
          setNotice("Processus repris.");
          await loadDetails(pid);
          return;
        }

        if (action === "kill") {
          await postJson("/api/action/kill", { pid, sig: 15 });
          setNotice("Signal envoyé (TERM).");
          return;
        }

        if (action === "renice") {
          const niceEl = root.querySelector("#pwNice");
          const nice = niceEl ? parseInt(niceEl.value || "10", 10) : 10;
          await postJson("/api/action/renice", { pid, nice });
          setNotice(`Nice appliqué: ${nice}.`);
          await loadDetails(pid);
          return;
        }
      } catch (e) {
        setNotice(`Erreur: ${e.message || e}`);
      }
    });
  });
}




function render(items) {
  currentItems = items;
  rowsEl.innerHTML = items.map(rowTemplate).join("");
  animateRowsIn(rowsEl);

  rowsEl.querySelectorAll(".row").forEach((el) => {
    el.addEventListener("click", () => {
      const pid = parseInt(el.getAttribute("data-pid"), 10);
      selectedPid = pid;
      const item = currentItems.find((entry) => entry.pid === pid);
      rowsEl.querySelectorAll(".row").forEach((row) => row.classList.remove("row-active"));
      el.classList.add("row-active");
      if (item) showDetails(item);
      loadDetails(pid);
    });
  });

  if (selectedPid) {
    const stillThere = currentItems.find((entry) => entry.pid === selectedPid);
    if (stillThere) {
      const activeRow = rowsEl.querySelector(`.row[data-pid="${selectedPid}"]`);
      if (activeRow) activeRow.classList.add("row-active");
      showDetails(stillThere);
      loadDetails(selectedPid);
    } else {
      selectedPid = null;
      detailCard.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">Processus terminé</div>
          <p class="empty-state-text">Le processus sélectionné n’existe plus.</p>
        </div>
      `;
    }
  }
}

async function load() {
  const params = new URLSearchParams({
    limit: String(parseInt(limitEl.value || "300", 10)),
    sort: sortEl.value,
    category: categoryEl.value,
    search: searchEl.value.trim(),
  });

  try {
    const res = await fetch(`/api/processes?${params.toString()}`, { cache: "no-store" });
    const data = await res.json();

    lastUpdate.textContent = new Date(data.ts * 1000).toLocaleTimeString();
    noteEl.textContent = data.note || "";

    updateStats(data.items || []);
    render(data.items || []);
    pulseLive();
  } catch (error) {
    noteEl.textContent = "Erreur de récupération des données.";
  }
}

function debounce(fn, ms) {
  let timeout = null;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), ms);
  };
}

const onFilterChange = debounce(() => load(), 180);

searchEl.addEventListener("input", onFilterChange);
categoryEl.addEventListener("change", load);
sortEl.addEventListener("change", () => {
  currentMode.textContent = sortLabel(sortEl.value);
  load();
});
limitEl.addEventListener("change", load);

intervalEl.addEventListener("input", () => {
  intervalLabel.textContent = `${intervalEl.value} ms`;
});
intervalEl.addEventListener("change", schedule);

btnPause.addEventListener("click", () => {
  paused = !paused;
  setPausedUI();
});

btnRefresh.addEventListener("click", load);

if (adminTokenEl) {
  adminTokenEl.value = adminToken;
  adminTokenEl.addEventListener("change", () => setAdminToken(adminTokenEl.value));
  adminTokenEl.addEventListener("input", () => setAdminToken(adminTokenEl.value));
}

function currentExportUrl(fmt) {
  const params = new URLSearchParams({
    format: fmt,
    category: categoryEl.value || "all",
    search: searchEl.value || "",
    limit: String(parseInt(limitEl.value || "300", 10)),
  });
  return `/api/export?${params.toString()}`;
}

if (btnExportJson) btnExportJson.addEventListener("click", () => window.open(currentExportUrl("json"), "_blank"));
if (btnExportCsv) btnExportCsv.addEventListener("click", () => window.open(currentExportUrl("csv"), "_blank"));

if (btnDiff) btnDiff.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/diff");
    const data = await res.json();
    const d = data.diff || {};
    const html = `
      <div><strong>Diff</strong> · ${escapeHtml(new Date(data.ts * 1000).toLocaleTimeString())}</div>
      <div class="mt-1 text-slate-300">started=${(d.started||[]).length} · stopped=${(d.stopped||[]).length} · changed=${(d.changed||[]).length} · new_suspicious=${(d.new_suspicious||[]).length}</div>
    `;
    setNotice(html, true);
  } catch (e) {
    setNotice("Erreur diff.");
  }
});

if (btnAudit) btnAudit.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/audit/recent?minutes=15");
    const data = await res.json();
    if (!data.available) {
      setNotice(`Auditd indisponible: ${data.error || "non disponible"}`);
      return;
    }
    const events = data.events || [];
    const top = events.slice(0, 8).map((ev) => `<li class="mono">${escapeHtml(new Date(ev.ts*1000).toLocaleTimeString())} · pid=${ev.pid ?? "–"} · ${escapeHtml(ev.comm || "")} · ${escapeHtml(ev.cmd || "")}</li>`).join("");
    const html = `
      <div><strong>Auditd</strong> · événements=${events.length}</div>
      <ul class="mt-2 list-disc pl-5 space-y-1 text-slate-300">${top || "<li>–</li>"}</ul>
    `;
    setNotice(html, true);
  } catch (e) {
    setNotice("Erreur auditd.");
  }
});

if (btnEbpf) btnEbpf.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/ebpf/events");
    const data = await res.json();
    if (!data.available) {
      setNotice(`eBPF log indisponible: ${escapeHtml(data.error || "non disponible")} (${escapeHtml(data.path || "")})`);
      return;
    }
    const events = data.events || [];
    const top = events.slice(-10).reverse().map((ev) => `<li class="mono">${escapeHtml(JSON.stringify(ev).slice(0, 220))}</li>`).join("");
    const html = `
      <div><strong>eBPF</strong> · événements=${events.length} · source=${escapeHtml(data.path || "")}</div>
      <ul class="mt-2 list-disc pl-5 space-y-1 text-slate-300">${top || "<li>–</li>"}</ul>
    `;
    setNotice(html, true);
  } catch (e) {
    setNotice("Erreur eBPF.");
  }
});

// Load server config once
(async () => {
  try {
    const res = await fetch("/api/config");
    configCache = await res.json();
    if (configCache && configCache.admin_actions_enabled === false) {
      setNotice("Admin token non configuré côté serveur: actions (kill/suspend/allowlist) désactivées.");
    }
  } catch (e) {}
})();

gsap.fromTo("header", { opacity: 0, y: -8 }, { opacity: 1, y: 0, duration: 0.35, ease: "power2.out" });
gsap.fromTo("main", { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.4, delay: 0.04, ease: "power2.out" });
gsap.fromTo(".stat-card", { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.35, stagger: 0.06, delay: 0.08, ease: "power2.out" });

intervalLabel.textContent = `${intervalEl.value} ms`;
currentMode.textContent = sortLabel(sortEl.value);
setPausedUI();
schedule();
load();
