const $ = (id) => document.getElementById(id);
const views = {
  scanner: $("scannerView"),
  rules: $("rulesView"),
  privacy: $("privacyView")
};
document.querySelectorAll(".nav-item").forEach(btn => btn.addEventListener("click", () => {
  document.querySelectorAll(".nav-item").forEach(b => b.classList.toggle("active", b === btn));
  Object.entries(views).forEach(([name, node]) => node.classList.toggle("hidden", name !== btn.dataset.view));
  $("pageTitle").textContent = btn.dataset.view === "scanner" ? "Threat Scanner" : btn.dataset.view === "rules" ? "Detection Rules" : "Privacy Center";
}));

async function checkApi() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) throw new Error();
    $("apiStatus").textContent = "Connected";
    $("engineStatus").textContent = "ONLINE";
  } catch {
    $("apiStatus").textContent = "API unavailable";
    $("engineStatus").textContent = "OFFLINE";
  }
}
checkApi();

$("emlFile").addEventListener("change", () => {
  $("fileName").textContent = $("emlFile").files[0]?.name || "No file selected";
});

$("scanButton").addEventListener("click", async () => {
  const email_text = $("emailText").value.trim();
  const url = $("urlText").value.trim();
  const file = $("emlFile").files[0];
  const btn = $("scanButton");
  if (!email_text && !url && !file) {
    showError("Add email text, enter a URL, or upload an .eml file.");
    return;
  }
  btn.disabled = true;
  btn.innerHTML = "<span>◌</span> Analyzing… <b>•••</b>";
  $("reportState").textContent = "ANALYZING";
  try {
    let response;
    if (file) {
      const form = new FormData();
      form.append("file", file);
      response = await fetch("/api/scan-eml", {method: "POST", body: form});
    } else {
      response = await fetch("/api/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({email_text, url})
      });
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Scan failed");
    renderResults(data);
  } catch (err) {
    showError(err.message || "Unable to connect to the API. Start the backend and retry.");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "<span>⌕</span> Analyze threat <b>→</b>";
  }
});

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function showError(message) {
  $("emptyState").classList.add("hidden");
  $("results").classList.remove("hidden");
  $("reportState").textContent = "SCAN ERROR";
  $("results").innerHTML = `<div class="finding"><strong>Unable to complete scan</strong><p>${esc(message)}</p></div>`;
}
function renderResults(data) {
  $("emptyState").classList.add("hidden");
  $("results").classList.remove("hidden");
  $("reportState").textContent = "REPORT READY";
  const score = Number(data.risk_score || 0);
  const color = score >= 55 ? "var(--red)" : score >= 25 ? "var(--amber)" : "var(--green)";
  const findings = data.findings || [];
  const findingHtml = findings.length ? findings.map(f => `
    <article class="finding">
      <div class="finding-top"><strong>${esc(f.code.replaceAll("_"," "))}</strong><span class="severity ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span></div>
      <p>${esc(f.message)}</p>
    </article>`).join("") : `<div class="no-findings">No configured heuristic indicators were triggered. This does not prove the message is safe.</div>`;
  const urlsHtml = (data.urls || []).map(u => `
    <div class="url-result"><div class="url-chip">${esc(u.url)}</div>
    <p class="report-note">${u.findings?.length ? u.findings.map(f => esc(f.code.replaceAll("_"," "))).join(" · ") : "No configured URL pattern indicators triggered."}</p></div>`).join("");
  const limitations = (data.limitations || []).map(s => `<li>${esc(s)}</li>`).join("");
  $("results").innerHTML = `
    <div class="verdict-row">
      <div class="score-ring" style="border-color:${color}"><strong>${score}</strong><small>/ 100</small></div>
      <div><div class="verdict-label">HEURISTIC ASSESSMENT</div><div class="verdict-title" style="color:${color}">${esc(data.verdict)}</div><div class="verdict-sub">${esc(data.score_type)}<br>Analysis time: ${esc(data.analysis_ms)} ms</div></div>
    </div>
    <div class="result-section-title">EVIDENCE / ${findings.length} INDICATORS</div>
    ${findingHtml}
    ${urlsHtml ? `<div class="result-section-title">URL INSPECTION / ${Number(data.url_count || 0)}</div>${urlsHtml}` : ""}
    ${data.email_headers ? `<div class="result-section-title">PARSED EMAIL HEADERS</div><div class="url-result">${Object.entries(data.email_headers).map(([k,v])=>`<p class="report-note"><b>${esc(k.toUpperCase())}:</b> ${esc(v || "Not present")}</p>`).join("")}</div>` : ""}
    <div class="result-section-title">LIMITATIONS</div><ul class="report-note">${limitations}</ul>
    <p class="report-note">${esc(data.privacy || "")}</p>`;
}
