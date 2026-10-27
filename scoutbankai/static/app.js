"use strict";
let token = "", snapshot = null, sessionGeneration = 0;
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
  const audit = $("audit-list"); audit.replaceChildren();
  if (!data.audit.length) audit.append(node("li", "No audit events recorded.", "empty"));
  for (const event of data.audit) {
    const item = node("li"); item.append(node("strong", readable(event.action)), node("time", date(event.time)), node("p", "#" + event.seq + " · " + event.actor), node("p", event.payment_id || event.mandate_id || event.agent_id || "Installation control")); audit.append(item);
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
async function refresh() { const generation = sessionGeneration; const data = await api("/v1/overview"); if (generation !== sessionGeneration || !token) return; const controls = await api("/v1/controls"); if (generation !== sessionGeneration || !token) return; render(data); renderControls(controls); }
function disconnect() { sessionGeneration++; token = ""; snapshot = null; $("token").value = ""; $("workspace").hidden = true; $("login").hidden = false; $("connection").textContent = "Disconnected"; $("connection").className = "connection"; $("limits-form").reset(); $("limit-feedback").textContent = ""; for (const id of ["payment-list", "agent-list", "mandate-list", "audit-list", "account-controls", "control-changes", "limit-account"]) $(id).replaceChildren(); }
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
$("export").addEventListener("click", () => { if (!snapshot) return; const blob = new Blob([JSON.stringify({exported_at: new Date().toISOString(), scope: "latest visible tenant events", events: snapshot.audit}, null, 2)], {type: "application/json"}); const url = URL.createObjectURL(blob), link = node("a"); link.href = url; link.download = "scoutbankai-audit-events.json"; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
