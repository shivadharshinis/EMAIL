"use strict";

// Keep the API endpoint in one place. The matching CORS origin is documented
// and narrowly configured in api.py for the local development server.
const API_BASE_URL = "http://127.0.0.1:8000";
const MAX_EMAIL_BYTES = 1024 * 1024;

const elements = {
  apiStatus: document.getElementById("api-status"),
  apiStatusText: document.getElementById("api-status-text"),
  providerHealthText: document.getElementById("provider-health-text"),
  healthButton: document.getElementById("health-button"),
  emailInput: document.getElementById("email-input"),
  inputFeedback: document.getElementById("input-feedback"),
  counter: document.getElementById("character-counter"),
  analyzeButton: document.getElementById("analyze-button"),
  analyzeLabel: document.getElementById("analyze-label"),
  analyzeSpinner: document.getElementById("analyze-spinner"),
  clearButton: document.getElementById("clear-button"),
  resultFeedback: document.getElementById("result-feedback"),
  emptyState: document.getElementById("empty-state"),
  results: document.getElementById("analysis-results"),
  copySummaryButton: document.getElementById("copy-summary-button"),
  copyReportButton: document.getElementById("copy-report-button"),
  overviewClassification: document.getElementById("overview-classification"),
  overviewClassificationNote: document.getElementById("overview-classification-note"),
  overviewRisk: document.getElementById("overview-risk"),
  overviewRiskNote: document.getElementById("overview-risk-note"),
  overviewIps: document.getElementById("overview-ips"),
  overviewFindings: document.getElementById("overview-findings"),
  riskBadge: document.getElementById("risk-badge"),
  overallAssessment: document.getElementById("overall-assessment"),
  riskReasons: document.getElementById("risk-reasons"),
  recommendedAction: document.getElementById("recommended-action"),
  mlBadge: document.getElementById("ml-badge"),
  mlExplanation: document.getElementById("ml-explanation"),
  senderStatus: document.getElementById("sender-status"),
  senderEvidence: document.getElementById("sender-evidence"),
  forensicSummary: document.getElementById("forensic-summary"),
  headerCount: document.getElementById("header-count"),
  headerFindings: document.getElementById("header-findings"),
  authenticationEvidence: document.getElementById("authentication-evidence"),
  ipStatus: document.getElementById("ip-status"),
  ipList: document.getElementById("ip-list"),
  threatCount: document.getElementById("threat-count"),
  reputationStatus: document.getElementById("reputation-status"),
  threatFindings: document.getElementById("threat-findings"),
  urlEvidence: document.getElementById("url-evidence"),
  forensicReport: document.getElementById("forensic-report"),
  limitations: document.getElementById("limitations"),
};

let latestResult = null;
let isAnalyzing = false;
let isCheckingHealth = false;

function displayString(value, fallback = "Not available") {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function appendText(parent, tagName, text, className = "") {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  node.textContent = text;
  parent.append(node);
  return node;
}

function setConnection(state, text) {
  elements.apiStatus.className = `connection-pill ${state}`;
  elements.apiStatusText.textContent = text;
}

function formatProviderStatus(value) {
  if (typeof value !== "string" || !value.trim()) return "unavailable";
  return value.split("_").join(" ").replace(/^./, (letter) => letter.toUpperCase());
}

async function readJsonResponse(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The backend returned a response that was not valid JSON.");
  }
}

async function checkHealth() {
  if (isCheckingHealth) return;
  isCheckingHealth = true;
  elements.healthButton.disabled = true;
  setConnection("is-checking", "Checking backend…");
  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const health = await readJsonResponse(response);
    if (!response.ok) {
      throw new Error(`Health check failed (HTTP ${response.status}).`);
    }
    if (health.status === "ok") {
      setConnection("is-connected", "Backend connected · model ready");
    } else if (health.status === "degraded") {
      setConnection("is-degraded", "Backend reachable · degraded");
    } else {
      setConnection("is-degraded", "Backend reachable · status unavailable");
    }
    const providers = health.providers && typeof health.providers === "object"
      ? health.providers
      : {};
    elements.providerHealthText.textContent =
      `IP geolocation: ${formatProviderStatus(providers.ip_geolocation)} · ` +
      `Threat reputation: ${formatProviderStatus(providers.threat_reputation)}`;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "Connection failed.";
    const corsHint = detail.toLowerCase().includes("fetch")
      ? " Check the backend and local CORS configuration."
      : "";
    setConnection("is-disconnected", `Backend unavailable${corsHint}`);
    elements.providerHealthText.textContent = "Provider status unavailable until backend health check succeeds.";
  } finally {
    isCheckingHealth = false;
    elements.healthButton.disabled = false;
  }
}

function updateCounter() {
  const rawEmail = elements.emailInput.value;
  const bytes = new TextEncoder().encode(rawEmail).byteLength;
  elements.counter.textContent = `${rawEmail.length.toLocaleString()} characters · ${bytes.toLocaleString()} B / 1 MiB`;
  elements.counter.classList.toggle("over-limit", bytes > MAX_EMAIL_BYTES);
  if (bytes > MAX_EMAIL_BYTES) {
    setInputFeedback("Message exceeds the 1 MiB limit. Shorten it yourself before analysis; it will not be truncated.", "error");
  } else if (!rawEmail.trim()) {
    setInputFeedback("Only analyze messages you are authorized to review.", "");
  } else {
    setInputFeedback("Message is within the size limit.", "success");
  }
}

function setInputFeedback(message, state) {
  elements.inputFeedback.textContent = message;
  elements.inputFeedback.className = `input-feedback${state ? ` ${state}` : ""}`;
}

function clearChildren(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function severityClass(severity) {
  if (severity === "warning") return "warning";
  if (severity === "error" || severity === "critical") return "error";
  return "informational";
}

function readableFindingTitle(identifier) {
  const knownTitles = {
    authentication_results_missing: "Authentication results missing",
    authentication_results_inconclusive: "Authentication results inconclusive",
    from_reply_to_domain_mismatch: "From / Reply-To domain mismatch",
    from_return_path_domain_mismatch: "From / Return-Path domain mismatch",
    spf_failure_reported: "SPF failure reported",
    dkim_failure_reported: "DKIM failure reported",
    dmarc_failure_reported: "DMARC failure reported",
    multiple_from_values: "Multiple From values",
    multiple_reply_to_values: "Multiple Reply-To values",
    multiple_return_path_values: "Multiple Return-Path values",
    multiple_sender_values: "Multiple sender values",
    sender_domain_mismatch: "Sender domain mismatch",
    malformed_sender_address: "Malformed sender address",
    malformed_sender_domain: "Malformed sender domain",
    url_visible_domain_mismatch: "Visible URL host differs",
    url_contains_userinfo: "URL contains user-information syntax",
    malformed_url: "URL host could not be parsed",
    malformed_url_host: "URL host could not be parsed",
    parse_error: "Message parsing issue",
    forensic_analysis_unavailable: "Header analysis unavailable",
    analysis_unavailable: "Threat analysis unavailable",
  };
  const rawTitle = displayString(identifier, "Finding");
  return knownTitles[rawTitle] || rawTitle
    .replaceAll("_", " ")
    .replace(/\b[a-z]/g, (letter) => letter.toUpperCase());
}

function renderFindings(container, findings, sourceLabel) {
  clearChildren(container);
  const validFindings = Array.isArray(findings)
    ? findings.filter((item) => item && typeof item === "object" && !Array.isArray(item))
    : [];
  if (!validFindings.length) {
    appendText(container, "p", `No ${sourceLabel.toLowerCase()} were reported by the backend.`, "small-copy muted");
    return;
  }
  for (const finding of validFindings) {
    const card = document.createElement("article");
    card.className = `finding-card ${severityClass(finding.severity)}`;
    const titleRow = document.createElement("div");
    titleRow.className = "finding-card-title";
    appendText(titleRow, "strong", readableFindingTitle(finding.code || finding.type));
    const severity = displayString(finding.severity, "unspecified").toLowerCase();
    appendText(titleRow, "span", severity, `finding-severity ${severityClass(severity)}`);
    card.append(titleRow);
    appendText(card, "p", displayString(finding.explanation, "No explanation was supplied."));
    if (finding.evidence && typeof finding.evidence === "object") {
      const evidence = document.createElement("p");
      evidence.className = "finding-evidence";
      evidence.textContent = `Evidence: ${JSON.stringify(finding.evidence)}`;
      card.append(evidence);
    }
    container.append(card);
  }
}

function renderIpInformation(ipInformation) {
  clearChildren(elements.ipList);
  if (!ipInformation || typeof ipInformation !== "object") {
    elements.ipStatus.textContent = "unavailable";
    appendText(elements.ipList, "p", "IP lookup information was not provided.", "small-copy muted");
    return [];
  }
  elements.ipStatus.textContent = displayString(ipInformation.lookup_status, "unavailable");
  const addresses = Array.isArray(ipInformation.addresses)
    ? ipInformation.addresses.filter((item) => item && typeof item === "object")
    : [];
  if (!addresses.length) {
    appendText(elements.ipList, "p", displayString(ipInformation.explanation, "No IP lookup result was provided."), "small-copy muted");
    return [];
  }
  for (const item of addresses) {
    const row = document.createElement("div");
    row.className = "ip-entry";
    appendText(row, "code", displayString(item.ip_address, "IP unavailable"));
    appendText(row, "span", `Lookup: ${displayString(item.lookup_status, "unavailable")}`);
    elements.ipList.append(row);
  }
  return addresses;
}

function renderSenderEvidence(senderAddresses) {
  clearChildren(elements.senderEvidence);
  if (!senderAddresses || typeof senderAddresses !== "object" || Array.isArray(senderAddresses)) {
    elements.senderStatus.textContent = "unavailable";
    appendText(elements.senderEvidence, "p", "Sender details were not returned by the backend.", "small-copy muted");
    return;
  }
  const headers = [
    ["from", "From"],
    ["reply_to", "Reply-To"],
    ["return_path", "Return-Path"],
    ["sender", "Sender"],
  ];
  let presentCount = 0;
  for (const [key, label] of headers) {
    const values = Array.isArray(senderAddresses[key])
      ? senderAddresses[key].filter((item) => item && typeof item === "object")
      : [];
    if (values.length) presentCount += 1;
    const value = values.length
      ? values.map((item) => {
        const name = typeof item.display_name === "string" ? item.display_name.trim() : "";
        const address = typeof item.address === "string" ? item.address.trim() : "";
        return name && address ? `${name} <${address}>` : address || name;
      }).filter(Boolean).join("\n")
      : "Not provided";
    const entry = document.createElement("div");
    entry.className = "evidence-item";
    appendText(entry, "span", label, "evidence-label");
    appendText(entry, "span", value, "evidence-value");
    elements.senderEvidence.append(entry);
  }
  elements.senderStatus.textContent = presentCount ? `${presentCount} header${presentCount === 1 ? "" : "s"} present` : "No sender details";
}

function renderAuthenticationEvidence(checks) {
  clearChildren(elements.authenticationEvidence);
  const validChecks = Array.isArray(checks)
    ? checks.filter((item) => item && typeof item === "object" && !Array.isArray(item))
    : [];
  if (!validChecks.length) {
    appendText(
      elements.authenticationEvidence,
      "p",
      "No SPF, DKIM, or DMARC check results were returned. Missing results do not mean authentication failed.",
      "small-copy muted",
    );
    return;
  }
  for (const check of validChecks) {
    const card = document.createElement("article");
    const result = displayString(check.result, "unknown").toLowerCase();
    card.className = `finding-card ${result === "fail" ? "error" : result === "pass" ? "informational" : ""}`;
    const titleRow = document.createElement("div");
    titleRow.className = "finding-card-title";
    const method = displayString(check.method, "unknown").toUpperCase();
    appendText(titleRow, "strong", `${method} result`);
    const badgeClass = result === "pass" ? "pass" : result === "fail" ? "fail" : "neutral";
    const badge = appendText(titleRow, "span", result, `auth-badge ${badgeClass}`);
    badge.setAttribute("aria-label", `${method}: ${result}`);
    card.append(titleRow);
    appendText(card, "p", `Reported by ${displayString(check.source, "unknown source")}. Authentication results are evidence to verify, not a verdict on their own.`);
    elements.authenticationEvidence.append(card);
  }
}

function renderUrlEvidence(urls) {
  clearChildren(elements.urlEvidence);
  const validUrls = Array.isArray(urls)
    ? urls.filter((item) => item && typeof item === "object" && !Array.isArray(item))
    : [];
  if (!validUrls.length) {
    appendText(elements.urlEvidence, "p", "No URLs were returned by the backend.", "small-copy muted");
    return;
  }
  for (const item of validUrls) {
    const card = document.createElement("article");
    card.className = "finding-card informational";
    const titleRow = document.createElement("div");
    titleRow.className = "finding-card-title";
    appendText(titleRow, "strong", displayString(item.host, "Host unavailable"));
    appendText(titleRow, "span", displayString(item.source, "source unavailable").replaceAll("_", " "), "auth-badge neutral");
    card.append(titleRow);
    if (typeof item.visible_text === "string" && item.visible_text.trim()) {
      appendText(card, "p", `Visible text: ${item.visible_text}`);
    }
    if (typeof item.url === "string" && item.url.trim()) {
      appendText(card, "code", item.url, "url-value");
    }
    elements.urlEvidence.append(card);
  }
}

function appendListItems(list, items, fallback) {
  clearChildren(list);
  const values = Array.isArray(items) ? items.filter((item) => typeof item === "string") : [];
  if (!values.length) {
    appendText(list, "li", fallback);
    return;
  }
  for (const value of values) appendText(list, "li", value);
}

function applyOverview(result, risk, addresses, headerFindings, threatFindings) {
  const prediction = displayString(result.ml_prediction, "unavailable");
  elements.overviewClassification.textContent = prediction;
  elements.overviewClassification.className = `card-value ${prediction === "spam" ? "class-spam" : prediction === "legitimate" ? "class-ham" : "risk-inconclusive"}`;
  elements.overviewClassificationNote.textContent = result.ml_label === 1
    ? "Model label 1 · review signal, not a verdict"
    : result.ml_label === 0
      ? "Model label 0 · not a safety guarantee"
      : "Model label unavailable";

  const level = displayString(risk.risk_level, "Inconclusive");
  elements.overviewRisk.textContent = level;
  elements.overviewRisk.className = `card-value ${riskClass(level)}`;
  elements.overviewRiskNote.textContent = "Cautious review priority";
  elements.overviewIps.textContent = String(addresses.length);
  elements.overviewIps.className = "card-value";
  elements.overviewFindings.textContent = String(headerFindings.length + threatFindings.length);
  elements.overviewFindings.className = "card-value";
}

function riskClass(level) {
  return {
    High: "risk-high",
    Medium: "risk-medium",
    Low: "risk-low",
    Inconclusive: "risk-inconclusive",
  }[level] || "risk-inconclusive";
}

function renderAnalysis(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("The backend returned an unexpected analysis result.");
  }
  const risk = result.risk_assessment;
  if (!risk || typeof risk !== "object") {
    throw new Error("The backend response is missing its risk assessment.");
  }
  const headerFindings = Array.isArray(result.forensic_findings) ? result.forensic_findings : [];
  const threatFindings = Array.isArray(result.threat_intelligence_findings)
    ? result.threat_intelligence_findings
    : [];
  const addresses = renderIpInformation(risk.ip_information);

  elements.riskBadge.textContent = displayString(risk.risk_level, "Inconclusive");
  elements.riskBadge.className = `severity-badge ${riskClass(risk.risk_level).replace("risk-", "")}`;
  elements.overallAssessment.textContent = displayString(result.overall_assessment);
  appendListItems(elements.riskReasons, risk.risk_reasons, "No specific risk reasons were returned.");
  elements.recommendedAction.textContent = displayString(risk.recommended_action, "No recommendation was provided.");

  const prediction = displayString(result.ml_prediction, "unavailable");
  elements.mlBadge.textContent = prediction;
  elements.mlBadge.className = `severity-badge ${prediction === "spam" ? "warning" : prediction === "legitimate" ? "low" : "inconclusive"}`;
  elements.mlExplanation.textContent = result.ml_label === 1
    ? "The model classified this message as spam (label 1). This is a text-classification signal, not proof of phishing or fraud."
    : result.ml_label === 0
      ? "The model classified this message as legitimate/ham (label 0). This does not prove it is safe."
      : "The model did not return a usable prediction.";

  renderSenderEvidence(result.sender_addresses);
  elements.forensicSummary.textContent = displayString(result.forensic_summary, "No header summary was provided.");
  renderAuthenticationEvidence(result.authentication_checks);
  elements.headerCount.textContent = String(headerFindings.length);
  elements.threatCount.textContent = String(threatFindings.length);
  renderFindings(elements.headerFindings, headerFindings, "header findings");
  renderFindings(elements.threatFindings, threatFindings, "local threat indicators");

  const reputation = result.threat_reputation;
  const reputationStatus = reputation && typeof reputation === "object"
    ? displayString(reputation.status, "unavailable")
    : "unavailable";
  elements.reputationStatus.textContent = `Live reputation status: ${reputationStatus}. Local indicators are heuristics, not verified reputation.`;
  appendListItems(elements.limitations, risk.limitations, "No limitations were returned.");
  renderUrlEvidence(result.detected_urls);
  elements.forensicReport.textContent = displayString(result.forensic_report, "No forensic report was returned.");

  applyOverview(result, risk, addresses, headerFindings, threatFindings);
  elements.emptyState.hidden = true;
  elements.results.hidden = false;
  elements.copyReportButton.disabled = typeof result.forensic_report !== "string" || !result.forensic_report;
  elements.copySummaryButton.disabled = false;
  latestResult = result;
}

function setResultFeedback(message, isSuccess = false) {
  elements.resultFeedback.textContent = message;
  elements.resultFeedback.className = `result-feedback${isSuccess ? " success" : ""}`;
  elements.resultFeedback.hidden = false;
}

async function analyzeEmail() {
  if (isAnalyzing) return;
  const rawEmail = elements.emailInput.value;
  if (!rawEmail.trim()) {
    setInputFeedback("Paste a non-empty email message before analysis.", "error");
    elements.emailInput.focus();
    return;
  }
  const bytes = new TextEncoder().encode(rawEmail).byteLength;
  if (bytes > MAX_EMAIL_BYTES) {
    setInputFeedback("Message exceeds the 1 MiB limit. Shorten it yourself before analysis; it was not submitted.", "error");
    elements.emailInput.focus();
    return;
  }

  isAnalyzing = true;
  elements.analyzeButton.disabled = true;
  elements.clearButton.disabled = true;
  elements.analyzeLabel.textContent = "Analyzing…";
  elements.analyzeSpinner.hidden = false;
  elements.resultFeedback.hidden = true;
  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ raw_email: rawEmail }),
      cache: "no-store",
    });
    const body = await readJsonResponse(response);
    if (!response.ok) {
      const detail = typeof body.detail === "string" ? body.detail : `Request failed (HTTP ${response.status}).`;
      throw new Error(detail);
    }
    renderAnalysis(body);
    setResultFeedback("Analysis complete. Findings are review signals, not a definitive verdict.", true);
  } catch (error) {
    const message = error instanceof Error ? error.message : "The analysis request failed.";
    setResultFeedback(message);
    if (!latestResult) {
      elements.emptyState.hidden = false;
      elements.results.hidden = true;
    }
  } finally {
    isAnalyzing = false;
    elements.analyzeButton.disabled = false;
    elements.clearButton.disabled = false;
    elements.analyzeLabel.textContent = "Analyze email";
    elements.analyzeSpinner.hidden = true;
  }
}

function buildSummary(result) {
  const risk = result.risk_assessment || {};
  const prediction = displayString(result.ml_prediction, "unavailable");
  const level = displayString(risk.risk_level, "Inconclusive");
  const reasons = Array.isArray(risk.risk_reasons)
    ? risk.risk_reasons.filter((item) => typeof item === "string")
    : [];
  const findingCount = (Array.isArray(result.forensic_findings) ? result.forensic_findings.length : 0)
    + (Array.isArray(result.threat_intelligence_findings) ? result.threat_intelligence_findings.length : 0);
  const ipStatus = risk.ip_information && typeof risk.ip_information === "object"
    ? displayString(risk.ip_information.lookup_status, "unavailable")
    : "unavailable";
  return [
    "Email analysis summary",
    `Classification: ${prediction} (label ${result.ml_label ?? "unavailable"})`,
    `Review priority: ${level}`,
    `Reported findings: ${findingCount}`,
    `IP lookup status: ${ipStatus}`,
    `Assessment: ${displayString(result.overall_assessment)}`,
    "Risk reasons:",
    ...(reasons.length ? reasons.map((reason) => `- ${reason}`) : ["- None returned"]),
    "This is a cautious review summary, not proof of malicious activity.",
  ].join("\n");
}

async function copyText(text, actionLabel) {
  try {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      throw new Error("Clipboard access is unavailable in this browser context.");
    }
    await navigator.clipboard.writeText(text);
    setResultFeedback(`${actionLabel} copied to clipboard.`, true);
  } catch {
    setResultFeedback(`Could not copy the ${actionLabel.toLowerCase()}. Check browser clipboard permissions.`);
  }
}

function clearResults() {
  if (isAnalyzing) return;
  elements.emailInput.value = "";
  updateCounter();
  latestResult = null;
  elements.results.hidden = true;
  elements.emptyState.hidden = false;
  elements.resultFeedback.hidden = true;
  elements.copyReportButton.disabled = true;
  elements.copySummaryButton.disabled = true;
  elements.overviewClassification.textContent = "—";
  elements.overviewClassification.className = "card-value neutral";
  elements.overviewClassificationNote.textContent = "Run an analysis to populate";
  elements.overviewRisk.textContent = "—";
  elements.overviewRisk.className = "card-value neutral";
  elements.overviewRiskNote.textContent = "No assessment yet";
  elements.overviewIps.textContent = "—";
  elements.overviewIps.className = "card-value neutral";
  elements.overviewFindings.textContent = "—";
  elements.overviewFindings.className = "card-value neutral";
  setInputFeedback("Only analyze messages you are authorized to review.", "");
}

elements.emailInput.addEventListener("input", updateCounter);
elements.analyzeButton.addEventListener("click", analyzeEmail);
elements.healthButton.addEventListener("click", checkHealth);
elements.clearButton.addEventListener("click", clearResults);
elements.copyReportButton.addEventListener("click", () => {
  if (latestResult && typeof latestResult.forensic_report === "string") {
    void copyText(latestResult.forensic_report, "Forensic report");
  }
});
elements.copySummaryButton.addEventListener("click", () => {
  if (latestResult) void copyText(buildSummary(latestResult), "Analysis summary");
});

updateCounter();
void checkHealth();
