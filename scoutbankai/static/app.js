"use strict";
let token = "", snapshot = null, sessionGeneration = 0, selectedAudit = null, auditSelection = 0;
let timelineSnapshot = null, timelineFilters = {}, timelineRequest = 0;
const $ = id => document.getElementById(id);
const readable = value => String(value || "").replaceAll("_", " ");
const date = value => new Date(value * 1000).toLocaleString();
function node(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function message(text, error = false) { $("message").textContent = text; $("message").className = "message" + (error ? " error" : ""); $("message").hidden = !text; }
async function api(path, body) {
  const headers = {Authorization: "Bearer " + token};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {method: body === undefined ? "GET" : "POST", headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "omit"});
  const data = await response.json();
  if (!response.ok) { if (response.status === 401) disconnect(); throw new Error(readable(data.error || "Request failed")); }
  return data;
}
async function busy(button, action) { button.disabled = true; try { await action(); } catch (e) { message(e.message || "Request failed", true); } finally { button.disabled = false; } }
function action(label, task, cls = "secondary") { const button = node("button", label, cls); button.addEventListener("click", () => busy(button, task)); return button; }
function money(amount, currency) { return new Intl.NumberFormat(undefined, {style: "currency", currency}).format(amount / 100); }
function render(data) {
  snapshot = data; $("login").hidden = true; $("workspace").hidden = false;
  $("connection").textContent = readable(data.role) + " connected"; $("connection").className = "connection connected";
  $("mode").textContent = data.mode === "development" ? "Development installation" : "Integrated deployment";
  $("updated").textContent = "Snapshot · " + date(data.updated_at);
  $("pause").hidden = data.role !== "operator"; $("pause").textContent = data.paused ? (data.mode === "integrated" ? "Request resume approval" : "Resume new dispatches") : "Pause new dispatches";
  $("verify").hidden = !["operator", "auditor"].includes(data.role);
  $("agent-count").textContent = data.agents.length; $("agent-detail").textContent = data.agents.filter(a => a.active).length + " enabled in this view";
  $("review-count").textContent = data.payments.filter(p => p.status === "review").length;
  $("pending-count").textContent = data.payments.filter(p => ["dispatching", "submitted", "unknown"].includes(p.status)).length;
  $("settled-count").textContent = data.payments.filter(p => p.status === "settled").length;
  $("supervisor-label").textContent = "Supervisor: " + data.supervisor;
  const paymentList = $("payment-list"); paymentList.replaceChildren();
  if (!data.payments.length) paymentList.append(node("p", "No payment requests recorded. Agent requests will appear here after authentication and policy checks.", "empty"));
  for (const payment of data.payments) {
    const row = node("article", undefined, "payment"), left = node("div"), right = node("div", undefined, "payment-right");
    left.append(node("h3", payment.reference), node("div", "Payee: " + payment.payee, "detail"), node("div", payment.id, "detail"), node("div", "Reason: " + readable(payment.reason), "detail"));
    right.append(node("span", money(payment.amount, payment.currency), "amount"), node("span", readable(payment.status), "status " + payment.status));
    row.append(left, right);
    if (payment.status === "review" && data.role === "reviewer") {
      const controls = node("div", undefined, "review-actions");
      for (const decision of ["approve", "reject"]) controls.append(action(decision === "approve" ? "Approve this request" : "Reject request", async () => {
        if (!window.confirm((decision === "approve" ? "Approve " : "Reject ") + money(payment.amount, payment.currency) + " to " + payment.payee + "?")) return;
        await api("/v1/payments/" + payment.id + "/review", {decision, request_hash: payment.request_hash}); await refresh(); message("Review recorded for " + payment.id + ".");
      }));
      row.append(controls);
    }
    if (["screening", "review", "queued"].includes(payment.status) && data.role === "operator") {
      const controls = node("div", undefined, "review-actions");
      controls.append(action("Cancel before dispatch", async () => {
        const reason = window.prompt("Why should this pending payment be cancelled? Enter at least five characters. The request cannot be reopened; a new payment would need its own authorisation.");
        if (reason === null) return;
        if (reason.trim().length < 5) throw new Error("Enter a cancellation reason of at least five characters.");
        if (!window.confirm("Cancel " + money(payment.amount, payment.currency) + " to " + payment.payee + "? This can succeed only before the bank dispatch begins.")) return;
        await api("/v1/payments/" + payment.id + "/cancel", {request_hash: payment.request_hash, reason: reason.trim()});
        await refresh(); message("Pending payment cancelled. Its reservation was released and the history was retained.");
      }));
      row.append(controls);
    }
    paymentList.append(row);
  }
  const agents = $("agent-list"); agents.replaceChildren();
  if (!data.agents.length) agents.append(node("p", "No agents registered. Register an agent’s public key through the operator API.", "empty"));
  for (const agent of data.agents) {
    const card = node("article", undefined, "identity-card");
    card.append(node("h3", agent.name), node("div", agent.id, "detail"), node("div", "Owner: " + agent.owner, "detail"), node("span", agent.active ? "Enabled" : "Suspended", "status " + (agent.active ? "settled" : "cancelled")));
    if (agent.active && data.role === "operator") card.append(action("Suspend agent", async () => {
      if (!window.confirm("Suspend this agent and cancel work that has not been dispatched?")) return;
      await api("/v1/agents/" + agent.id + "/suspend", {}); await refresh(); message("Agent suspended. In-flight payments still require reconciliation.");
    }));
    agents.append(card);
  }
  const mandates = $("mandate-list"); mandates.replaceChildren();
  if (!data.mandates.length) mandates.append(node("p", "No customer permissions recorded.", "empty"));
  for (const mandate of data.mandates) {
    const card = node("article", undefined, "identity-card");
    card.append(node("h3", mandate.id), node("div", "Customer: " + mandate.customer, "detail"), node("div", "Expires: " + date(mandate.expires), "detail"), node("span", mandate.revoked ? "Revoked" : mandate.expires <= data.updated_at ? "Expired" : "Active", "status"));
    if (!mandate.revoked && data.role === "operator") card.append(action("Revoke permission", async () => {
      if (!window.confirm("Revoke this permission and cancel undispatched work?")) return;
      await api("/v1/mandates/" + mandate.id + "/revoke", {}); await refresh(); message("Permission revoked.");
    }));
    mandates.append(card);
  }
}
function policyText(policy, currency) {
  return "Per payment: " + money(policy.per_payment_minor, currency) + " · Rolling 24 hours: " + money(policy.rolling_day_minor, currency) + " · Outstanding: " + money(policy.max_pending_minor, currency) + " · Requests per minute: " + policy.max_payments_per_minute + " · Dispatch within: " + policy.max_request_age_seconds + " seconds · Independent review: " + (policy.require_review ? "every payment" : "when other controls require it");
}
function renderControls(data) {
  const role = snapshot.role, accounts = $("account-controls"), changes = $("control-changes"), select = $("limit-account");
  const selected = select.value;
  accounts.replaceChildren(); changes.replaceChildren(); select.replaceChildren();
  $("limits-editor").hidden = role !== "operator"; $("verify-journal").hidden = !["operator", "auditor"].includes(role);
  if (!data.accounts.length) accounts.append(node("p", "No accounts registered.", "empty"));
  for (const account of data.accounts) {
    const option = node("option", account.account + " (" + account.currency + ")"); option.value = account.account; select.append(option);
    const card = node("article", undefined, "identity-card");
    card.append(node("h3", account.account + " · " + account.currency), node("span", account.frozen ? "Frozen" : "Open", "status " + (account.frozen ? "cancelled" : "settled")));
    card.append(node("p", account.policy ? policyText(account.policy, account.currency) : "Account limits have not been approved. Integrated deployments block new payments until limits are approved.", "detail"));
    if (role === "operator") card.append(action(account.frozen ? "Request account reopening" : "Freeze account", async () => {
      if (account.frozen) {
        const reason = window.prompt("Explain why this account can be reopened:"); if (!reason) return;
        await api("/v1/control-changes", {action: "unfreeze_account", account_id: account.account, reason});
        await refresh(); message("Reopening request submitted. A separate reviewer must approve it.");
      } else {
        if (!window.confirm("Freeze " + account.account + " and cancel undispatched work? In-flight payments will still be reconciled.")) return;
        await api("/v1/accounts/" + account.account + "/freeze", {}); await refresh(); message("Account frozen. In-flight payments still require reconciliation.");
      }
    }));
    accounts.append(card);
  }
  if ([...select.options].some(o => o.value === selected)) select.value = selected;
  if (!data.changes.length) changes.append(node("p", "No control changes proposed.", "empty"));
  for (const change of data.changes) {
    const payload = change.payload, expired = change.expires <= snapshot.updated_at;
    const card = node("article", undefined, "identity-card");
    card.append(node("h3", readable(payload.action)), node("span", change.status === "pending" && expired ? "Expired" : change.status, "status"),
      node("p", "Target: " + (payload.account_id || "Entire bank tenant"), "detail"), node("p", "Reason: " + payload.reason, "detail"),
      node("p", "Proposed by: " + change.proposer + " · Expires: " + date(change.expires), "detail"));
    if (payload.limits) {
      const account = data.accounts.find(a => a.account === payload.account_id);
      // Accounts outside the bounded snapshot still have an exact, readable policy.
      card.append(node("p", account ? policyText(payload.limits, account.currency) : JSON.stringify(payload.limits), "detail"));
    }
    card.append(node("p", "Change hash: " + change.request_hash, "detail"));
    if (payload.restores_change_id) card.append(node("p", "Restores limits from: " + payload.restores_change_id, "detail"));
    if (role === "operator" && change.status === "approved" && payload.action === "account_limits") {
      const current = data.accounts.find(a => a.account === payload.account_id);
      if (current && JSON.stringify(current.policy) !== JSON.stringify(payload.limits)) card.append(action("Request restore of these limits", () => requestRestore(change.id, change.request_hash, payload.account_id, payload.limits)));
    }
    if (role === "reviewer" && change.status === "pending" && !expired) {
      const buttons = node("div", undefined, "actions");
      for (const decision of ["approve", "reject"]) buttons.append(action(decision === "approve" ? "Approve control change" : "Reject control change", async () => {
        if (!window.confirm((decision === "approve" ? "Approve " : "Reject ") + readable(payload.action) + " for " + (payload.account_id || "this bank") + "? Check the displayed policy and reason before proceeding.")) return;
        await api("/v1/control-changes/" + change.id + "/review", {decision, request_hash: change.request_hash}); await refresh(); message("Control change " + (decision === "approve" ? "approved" : "rejected") + ".");
      }));
      card.append(buttons);
    }
    changes.append(card);
  }
}
const findingLabels = {
  threshold_exceeded: "Amount exceeds the review threshold", account_review_required: "Account policy requires review",
  supervisor_review_required: "The supervisor requires review", budget_near_limit: "Delegated budget is near its limit",
  high_velocity: "Request frequency needs review", unusual_pattern: "Unusual pattern supported by evidence",
  insufficient_context: "Insufficient context for a decision", peer_disagreement: "Peer claims are disputed or uncertain"
};
async function requestRestore(changeId, sourceHash, accountId, limits) {
  const generation = sessionGeneration;
  const current = await api("/v1/accounts/" + accountId + "/controls");
  if (generation !== sessionGeneration || !token) return;
  if (!window.confirm("Request restoration of these previously approved limits for " + accountId + "?\n\n" + policyText(limits, current.currency) + "\n\nA separate reviewer must approve this new change. Payments, freezes and history will remain as they are.")) return;
  const reason = window.prompt("Explain why these earlier limits should be restored (at least five characters):");
  if (reason === null) return;
  if (reason.trim().length < 5) throw new Error("Enter a restoration reason of at least five characters.");
  await api("/v1/control-changes/" + changeId + "/restore", {source_hash: sourceHash, expected_version: current.version, reason: reason.trim()});
  await refresh(); message("Restoration requested. A separate reviewer must approve it before limits change. History is retained.");
}
function timelineInputs() {
  const filters = {};
  for (const [key, id] of [["actor", "timeline-actor"], ["action", "timeline-action"], ["object_id", "timeline-object"]]) {
    if ($(id).value.trim()) filters[key] = $(id).value.trim();
  }
  for (const [key, id] of [["from_time", "timeline-from"], ["to_time", "timeline-to"]]) {
    if ($(id).value) filters[key] = Math.floor(new Date($(id).value).getTime() / 1000);
  }
  if (filters.from_time !== undefined && filters.to_time !== undefined && filters.from_time > filters.to_time) throw new Error("The start must be before the end of the time range.");
  return filters;
}
function renderTimeline() {
  const list = $("audit-list"); list.replaceChildren();
  for (const event of timelineSnapshot.events) {
    const item = node("li");
    item.append(node("strong", readable(event.action)), node("time", date(event.time)),
      node("p", "Event #" + event.seq + " · Actor: " + event.actor),
      node("p", event.payment_id || event.change_id || event.account_id || event.mandate_id || event.agent_id || event.payee_id || "Installation control"));
    if (event.reason) item.append(node("p", "Reason: " + readable(event.reason)));
    if (event.round) item.append(node("p", "Audit round " + event.round + " · " + (event.mode === "rules" ? "Deterministic checks" : "Model assessment") + " · " + (event.model || "Model not recorded")));
    for (const [label, state] of [["Before", event.before_state], ["After", event.after_state]]) {
      if (!state) continue;
      const view = node("div", undefined, "historical-state"); view.append(node("h4", label + " · version " + state.version));
      if (state.currency) view.append(node("p", state.limits ? policyText(state.limits, state.currency) : "No account limits were configured."), node("p", state.frozen ? "Account frozen" : "Account open"));
      else if (typeof state.paused === "boolean") view.append(node("p", state.paused ? "New dispatches paused" : "New dispatches enabled"));
      item.append(view);
    }
    const detail = node("details"); detail.append(node("summary", "View recorded details"));
    const values = Object.fromEntries(Object.entries(event).filter(([key]) => !["tenant", "seq", "actor", "action", "time"].includes(key)));
    detail.append(node("pre", JSON.stringify(values, null, 2), "event-details")); item.append(detail);
    if (event.payment_id && event.action.startsWith("cross_audit_")) item.append(action("Inspect audit rounds", () => openAudit(event.payment_id)));
    if (snapshot.role === "operator" && event.action === "control_change_approved" && event.action_type === "account_limits") {
      item.append(action("Request restore of recorded limits", async () => {
        const generation = sessionGeneration, change = await api("/v1/control-changes/" + event.change_id);
        if (generation !== sessionGeneration || !token) return;
        await requestRestore(change.id, change.request_hash, change.payload.account_id, change.payload.limits);
      }));
    }
    list.append(item);
  }
  if (!timelineSnapshot.events.length) list.append(node("li", "No recorded events match these filters.", "empty"));
  $("timeline-feedback").textContent = timelineSnapshot.events.length + " events loaded through snapshot #" + timelineSnapshot.snapshot_seq + ". Returned event signatures checked. Use Verify chain for the complete chain.";
  $("timeline-older").hidden = !timelineSnapshot.next_before_seq;
}
async function loadTimeline(reset = true) {
  const generation = sessionGeneration, request = ++timelineRequest;
  const query = {...timelineFilters};
  if (!reset && timelineSnapshot) Object.assign(query, {snapshot_seq: timelineSnapshot.snapshot_seq, before_seq: timelineSnapshot.next_before_seq});
  const page = await api("/v1/timeline/search", query);
  if (generation !== sessionGeneration || request !== timelineRequest || !token) return;
  timelineSnapshot = {...page, events: reset || !timelineSnapshot ? page.events : [...timelineSnapshot.events, ...page.events]};
  renderTimeline();
}
$("timeline-form").addEventListener("submit", event => {
  event.preventDefault(); busy(event.submitter, async () => {
    try { timelineFilters = timelineInputs(); await loadTimeline(); }
    catch (error) { $("timeline-feedback").textContent = error.message; $("timeline-feedback").focus(); throw error; }
  });
});
$("timeline-reset").addEventListener("click", event => busy(event.currentTarget, async () => { $("timeline-form").reset(); timelineFilters = {}; await loadTimeline(); }));
$("timeline-older").addEventListener("click", event => busy(event.currentTarget, () => loadTimeline(false)));
function renderCouncil(data) {
  $("council-mode").textContent = data.mode === "rules" ? "Deterministic rules" : "AI model audits";
  $("council-description").textContent = data.rounds + " rounds · 3 audit roles · " +
    (data.mode === "rules" ? "Local checks; no model calls." : data.distinct_models + " configured model IDs. Separate roles can share the same model and its mistakes.");
  const scores = $("audit-scores"); scores.replaceChildren();
  for (const score of data.scores) {
    const card = node("article", undefined, "audit-score");
    card.append(node("h3", readable(score.role)), node("strong", score.evaluated ? score.points + (Math.abs(score.points) === 1 ? " point" : " points") : "Not yet scored"),
      node("p", score.evaluated + " independently assessed requests", "detail"),
      node("p", score.evaluated ? "Average: " + score.average_points.toFixed(1) + " / request · range −10 to +10" : "An independent evaluator must label the evidence first.", "detail"),
      node("p", data.configured_models[score.role] || "rules-v1", "detail"));
    scores.append(card);
  }
  const runs = $("audit-runs"); runs.replaceChildren();
  if (!data.runs.length) runs.append(node("p", "No cross-audits recorded yet.", "empty"));
  for (const run of data.runs) {
    const card = node("article", undefined, "identity-card");
    card.append(node("h4", run.payment), node("p", readable(run.status) + " · " + readable(run.reason) + " · " + run.rounds + " planned rounds", "detail"),
      action("View audit rounds", () => openAudit(run.payment)));
    runs.append(card);
  }
}
async function openAudit(payment, focus = true) {
  const generation = sessionGeneration, selection = ++auditSelection;
  const data = await api("/v1/payments/" + payment + "/audits");
  if (generation !== sessionGeneration || selection !== auditSelection || !token) return;
  selectedAudit = data;
  $("audit-detail").hidden = false; $("audit-detail-title").textContent = "Cross-audit · " + data.payment_id;
  const summary = $("audit-detail-summary"); summary.replaceChildren();
  summary.append(node("p", readable(data.status) + " · " + readable(data.reason), "detail"),
    node("p", "Request hash: " + data.request_hash, "detail"), node("p", "Context hash: " + data.context_hash, "detail"),
    node("p", "Result hash: " + (data.result_hash || "Not completed"), "detail"));
  const context = node("details"); context.append(node("summary", "Original audit context"));
  for (const [key, value] of Object.entries(data.context)) context.append(node("p", readable(key) + ": " + value, "detail"));
  summary.append(context);
  const rounds = $("audit-rounds"); rounds.replaceChildren();
  for (let number = 1; number <= data.rounds; number++) {
    const group = node("details", undefined, "audit-round"); group.open = number === data.rounds;
    const reports = data.reports.filter(r => r.round === number);
    group.append(node("summary", "Round " + number + (number === 1 ? " · independent assessments" : " · peer checks")));
    if (!reports.length) group.append(node("p", "This round has no recorded reports.", "detail"));
    for (const entry of reports) {
      const card = node("article", undefined, "audit-report");
      card.append(node("h4", readable(entry.role) + " · " + readable(entry.status)), node("p", "Model: " + entry.model, "detail"));
      if (entry.report) {
        card.append(node("p", entry.report.require_review ? "Requires independent review" : "No review trigger reported", "status " + (entry.report.require_review ? "review" : "settled")),
          node("p", entry.report.summary, "detail"));
        for (const code of entry.report.finding_codes) card.append(node("p", findingLabels[code], "detail"));
        for (const peer of entry.report.peer_checks) card.append(node("p", "Checked " + peer.role + ": " + readable(peer.verdict) + " · " + peer.report_hash, "detail"));
      } else card.append(node("p", "No usable report. This request requires independent review.", "detail"));
      card.append(node("p", "Report hash: " + entry.report_hash, "detail")); group.append(card);
    }
    rounds.append(group);
  }
  const evaluation = $("audit-evaluation"); evaluation.replaceChildren();
  $("evaluation-form").reset(); $("evaluation-feedback").textContent = "";
  $("evaluation-form").hidden = snapshot.role !== "evaluator" || data.status !== "completed" || !!data.feedback;
  if (data.feedback) {
    const label = data.feedback.label;
    evaluation.append(node("h4", "Independent assessment recorded"),
      node("p", data.feedback.evaluator + " · " + date(data.feedback.created), "detail"),
      node("p", "Evidence: " + label.evidence_reference, "detail"), node("p", label.explanation, "detail"),
      node("p", label.review_required ? "Confirmed: review was required." : "Confirmed: no review trigger was established.", "detail"));
    for (const code of label.confirmed_findings) evaluation.append(node("p", findingLabels[code], "detail"));
  } else evaluation.append(node("p", "Not independently scored. A separate evaluator can assess a completed audit.", "detail"));
  if (focus) $("audit-detail-title").focus();
}
for (const [code, label] of Object.entries(findingLabels)) {
  const wrapper = node("label", undefined, "checkbox-label"), input = node("input");
  input.type = "checkbox"; input.value = code; input.name = "confirmed-finding";
  wrapper.append(input, document.createTextNode(label)); $("evaluation-findings").append(wrapper);
}
$("evaluation-form").addEventListener("submit", event => {
  event.preventDefault();
  const selected = selectedAudit, generation = sessionGeneration;
  if (!selected || snapshot.role !== "evaluator") return;
  const findings = [...$("evaluation-findings").querySelectorAll("input:checked")].map(input => input.value);
  const required = $("evaluation-verdict").value === "yes";
  if (required !== !!findings.length) {
    $("evaluation-feedback").textContent = "Confirm at least one finding when review was required, or clear all findings when no trigger was established.";
    $("evaluation-feedback").focus(); return;
  }
  busy(event.submitter, async () => {
    await api("/v1/payments/" + selected.payment_id + "/audit-feedback", {
      result_hash: selected.result_hash, review_required: required, confirmed_findings: findings,
      evidence_reference: $("evaluation-reference").value.trim(), explanation: $("evaluation-explanation").value.trim()
    });
    if (generation !== sessionGeneration || !token) return;
    await refresh(); await openAudit(selected.payment_id, false); message("Independent assessment recorded. Points updated; payment authority is unchanged.");
  });
});
async function refresh() { const generation = sessionGeneration; const data = await api("/v1/overview"); if (generation !== sessionGeneration || !token) return; const controls = await api("/v1/controls"); if (generation !== sessionGeneration || !token) return; const council = await api("/v1/audit-agents"); if (generation !== sessionGeneration || !token) return; render(data); renderControls(controls); renderCouncil(council); await loadTimeline(); }
function disconnect() { sessionGeneration++; auditSelection++; timelineRequest++; token = ""; snapshot = null; selectedAudit = null; timelineSnapshot = null; timelineFilters = {}; $("timeline-form").reset(); $("timeline-feedback").textContent = ""; $("timeline-older").hidden = true; $("token").value = ""; $("workspace").hidden = true; $("login").hidden = false; $("connection").textContent = "Disconnected"; $("connection").className = "connection"; $("limits-form").reset(); $("limit-feedback").textContent = ""; $("evaluation-form").reset(); $("evaluation-feedback").textContent = ""; $("audit-detail").hidden = true; for (const id of ["payment-list", "agent-list", "mandate-list", "audit-list", "account-controls", "control-changes", "limit-account", "audit-scores", "audit-runs", "audit-detail-summary", "audit-rounds", "audit-evaluation"]) $(id).replaceChildren(); }
$("connect-form").addEventListener("submit", event => { event.preventDefault(); sessionGeneration++; token = $("token").value.trim(); $("token").value = ""; busy(event.submitter, async () => { await refresh(); message(""); }); });
$("refresh").addEventListener("click", event => busy(event.currentTarget, refresh));
$("disconnect").addEventListener("click", () => { disconnect(); message(""); });
$("pause").addEventListener("click", event => busy(event.currentTarget, async () => { const paused = !snapshot.paused;
  if (!paused && snapshot.mode === "integrated") {
    const reason = window.prompt("Explain why dispatch can resume:"); if (!reason) return;
    await api("/v1/control-changes", {action: "resume_bank", reason}); await refresh(); message("Resume requested. A separate reviewer must approve it."); return;
  }
  if (!window.confirm(paused ? "Pause new dispatches? Payments already sent to the bank will still be reconciled." : "Resume new dispatches?")) return;
  await api("/v1/pause", {paused}); await refresh(); message(paused ? "New dispatches paused. Reconciliation continues." : "New dispatches resumed.");
}));
$("limits-form").addEventListener("submit", event => { event.preventDefault(); busy(event.submitter, async () => {
  $("limit-feedback").textContent = "Submitting for review…";
  try {
    const limits = {per_payment_minor: $("limit-payment").valueAsNumber, rolling_day_minor: $("limit-day").valueAsNumber,
      max_pending_minor: $("limit-pending").valueAsNumber, max_payments_per_minute: $("limit-rate").valueAsNumber,
      max_request_age_seconds: $("limit-age").valueAsNumber, require_review: $("limit-review").checked};
    if (limits.per_payment_minor > Math.min(limits.rolling_day_minor, limits.max_pending_minor)) throw new Error("Per-payment limit must fit within both aggregate limits.");
    await api("/v1/control-changes", {action: "account_limits", account_id: $("limit-account").value, limits, reason: $("limit-reason").value});
    await refresh(); $("limit-feedback").textContent = "Submitted. A separate reviewer must approve these limits before they take effect.";
  } catch (e) { $("limit-feedback").textContent = e.message; throw e; }
}); });
$("verify-journal").addEventListener("click", event => busy(event.currentTarget, async () => { const result = await api("/v1/journal/verify"); message("Reservations verified for " + result.payments_checked + " payments. Customer balances remain with the connected bank."); }));
$("verify").addEventListener("click", event => busy(event.currentTarget, async () => { const result = await api("/v1/audit/verify"); message("Audit chain verified through event " + result.checkpoint.seq + ". Checkpoint: " + result.checkpoint.hash + ". Save this outside the installation."); }));
$("export").addEventListener("click", () => { if (!timelineSnapshot) return; const blob = new Blob([JSON.stringify({exported_at: new Date().toISOString(), scope: "loaded filtered tenant events", filters: timelineFilters, ...timelineSnapshot}, null, 2)], {type: "application/json"}); const url = URL.createObjectURL(blob), link = node("a"); link.href = url; link.download = "scoutbankai-audit-events.json"; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
