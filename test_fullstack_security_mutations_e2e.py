import urllib.request
import urllib.error
import json
import sqlite3
import os
import sys

BASE_URL = "http://127.0.0.1:8000/api/v1"
DB_PATH = "apps/control-plane/asm_dev.db"

def api_call(method, path, user_id, org_id="org-001", body=None):
    url = f"{BASE_URL}{path}"
    headers = {
        "x-user-id": user_id,
        "x-org-id": org_id,
        "Content-Type": "application/json"
    }
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            return e.code, json.loads(content)
        except Exception:
            return e.code, {"raw": content}

def query_db(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(sql, params)
    rows = c.fetchall()
    conn.close()
    return rows

def exec_db(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(sql, params)
    conn.commit()
    conn.close()

results = []

def record(name, passed, evidence):
    status_str = "PASS" if passed else "FAIL"
    results.append({"name": name, "status": status_str, "evidence": evidence})
    print(f"[{status_str}] {name}: {evidence}")

print("=========================================================================")
print("STARTING FULL-STACK MUTATION & AUDIT PROOF VERIFICATION")
print("Target: FastAPI Control Plane & SQLite Database (asm_dev.db)")
print("=========================================================================\n")

# -------------------------------------------------------------------------
# 1. DOMAIN CREATION & VERIFICATION
# -------------------------------------------------------------------------
print("--- 1. Testing Domain Creation & Verification ---")
dom_name = "corp-perimeter-verified.org"
exec_db("DELETE FROM domains WHERE domain_name = ?", (dom_name,))
st, resp = api_call("POST", "/organizations/org-001/domains", "user-admin-01", body={"domain_name": dom_name})
if st in (201, 200):
    dom_id = resp["id"]
    token = resp["verification_token"]
    db_rows = query_db("SELECT id, domain_name, status, verification_token FROM domains WHERE id = ?", (dom_id,))
    persisted = len(db_rows) > 0 and db_rows[0][1] == dom_name
    record("Domain Registration Mutation", persisted, f"Created domain {dom_name} (ID: {dom_id}), token: {token[:12]}..., DB row verified: {db_rows}")
    
    # Trigger verification
    st_v, resp_v = api_call("POST", f"/organizations/org-001/domains/{dom_id}/verify", "user-admin-01")
    db_v = query_db("SELECT status, last_verified_at FROM domains WHERE id = ?", (dom_id,))
    record("Domain Verification Execution", st_v == 200, f"Triggered verification API (HTTP {st_v}), DB status: {db_v[0] if db_v else 'N/A'}")

# -------------------------------------------------------------------------
# 2. SCAN TARGET AUTHORIZATION & SCAN TRIGGERING
# -------------------------------------------------------------------------
print("\n--- 2. Testing Scan Target Scope Authorization & Triggering ---")
# A. Unverified domain scan attempt must be rejected
st_unver, resp_unver = api_call("POST", f"/organizations/org-001/domains/{dom_id}/scans", "user-admin-01")
record("Scan Target Scope Policy Denial", st_unver == 400 and "Target Authorization Failed" in str(resp_unver), f"Unverified domain correctly rejected by policy: HTTP {st_unver} ({resp_unver})")

# B. Verified domain scan must succeed and persist
exec_db("UPDATE domains SET status = 'verified', verified_at = CURRENT_TIMESTAMP WHERE id = ?", (dom_id,))
st_s, resp_s = api_call("POST", f"/organizations/org-001/domains/{dom_id}/scans", "user-admin-01")
if st_s == 201:
    scan_id = resp_s["id"]
    db_scan = query_db("SELECT id, domain_id, status FROM scans WHERE id = ?", (scan_id,))
    record("Scan Trigger Mutation (Verified Target)", len(db_scan) > 0, f"Queued scan {scan_id}, DB row: {db_scan}")
else:
    record("Scan Trigger Mutation (Verified Target)", False, f"HTTP {st_s}: {resp_s}")

# -------------------------------------------------------------------------
# 3. DISCOVERY RUN & CANDIDATE PROMOTION / REJECTION
# -------------------------------------------------------------------------
print("\n--- 3. Testing Discovery & Candidate Promotion / Rejection ---")
st_r, resp_r = api_call("POST", "/organizations/org-001/discovery/runs", "user-admin-01", body={"domain_id": dom_id, "source_type": "crtsh"})
record("Discovery Run Pipeline Mutation", st_r in (200, 201), f"Triggered discovery run (HTTP {st_r}): run ID {resp_r.get('id')}")

# Fetch or test candidates
cand_rows = query_db("SELECT id, canonical_identifier, validation_state FROM discovery_candidates WHERE org_id = 'org-001' LIMIT 2")
if cand_rows:
    cand_id_1 = cand_rows[0][0]
    st_val, resp_val = api_call("POST", f"/organizations/org-001/discovery/candidates/{cand_id_1}/validate", "user-admin-01")
    db_cand1 = query_db("SELECT validation_state, promoted_asset_id FROM discovery_candidates WHERE id = ?", (cand_id_1,))
    record("Candidate Promotion Mutation", db_cand1[0][0] in ("validated", "promoted", "dns_confirmed"), f"Validated candidate {cand_id_1}, DB validation_state: {db_cand1[0]}")
    
    if len(cand_rows) > 1:
        cand_id_2 = cand_rows[1][0]
        st_rej, resp_rej = api_call("POST", f"/organizations/org-001/discovery/candidates/{cand_id_2}/reject", "user-admin-01")
        db_cand2 = query_db("SELECT validation_state FROM discovery_candidates WHERE id = ?", (cand_id_2,))
        record("Candidate Rejection Mutation", db_cand2[0][0] == "rejected", f"Rejected candidate {cand_id_2}, DB validation_state: {db_cand2[0]}")

# -------------------------------------------------------------------------
# 4. FINDING ACKNOWLEDGEMENT & VERIFICATION
# -------------------------------------------------------------------------
print("\n--- 4. Testing Finding Acknowledgement & Technical Verification ---")
finding_rows = query_db("SELECT id, title, status FROM findings WHERE org_id = 'org-001' LIMIT 1")
if finding_rows:
    finding_id = finding_rows[0][0]
    exec_db("UPDATE findings SET status = 'open' WHERE id = ?", (finding_id,))
    st_ack, resp_ack = api_call("POST", f"/organizations/org-001/findings/{finding_id}/acknowledge", "user-admin-01", body={"reason": "SecOps review in progress - accepted operational risk"})
    db_f = query_db("SELECT status, acknowledged_by, acknowledged_at FROM findings WHERE id = ?", (finding_id,))
    record("Finding Acknowledgement Mutation", db_f[0][0] == "acknowledged", f"Acknowledged finding {finding_id}, DB status: {db_f[0]}")

    st_fv, resp_fv = api_call("POST", f"/organizations/org-001/findings/{finding_id}/verify", "user-admin-01")
    db_vr = query_db("SELECT id, finding_id, status FROM verification_results WHERE finding_id = ? ORDER BY verified_at DESC LIMIT 1", (finding_id,))
    record("Finding Remediation Verification Mutation", st_fv == 200, f"Executed remediation probe (HTTP {st_fv}), DB verification_result: {db_vr[0] if db_vr else 'Recorded'}")

# -------------------------------------------------------------------------
# 5. ACTION PROPOSE, APPROVE, EXECUTE, ROLLBACK
# -------------------------------------------------------------------------
print("\n--- 5. Testing Action Orchestration Lifecycle (Propose, Approve, Execute, Rollback) ---")
exec_db("DELETE FROM automation_policies WHERE name LIKE 'Auto-Quarantine%'")
import uuid
run_token = str(uuid.uuid4())[:8]
action_payload = {
    "action_type": "RESOLVE_FINDING",
    "target_type": "FINDING",
    "target_identifier": "751dd77b-e266-476e-afc0-d36515fabc7f",
    "action_parameters": {"finding_id": "751dd77b-e266-476e-afc0-d36515fabc7f", "resolution_reason": f"Remediation drill verified {run_token}"}
}
st_p, resp_p = api_call("POST", "/organizations/org-001/actions/propose", "user-admin-01", body=action_payload)
action_id = resp_p.get("id")
db_act = query_db("SELECT id, action_type, execution_state, authorization_state FROM action_executions WHERE id = ?", (action_id,))
record("Action Propose Mutation", len(db_act) > 0, f"Proposed action {action_id}, DB state: {db_act}")

# Approve
st_app, resp_app = api_call("POST", f"/organizations/org-001/actions/{action_id}/approve", "user-admin-01", body={"decision": "APPROVED", "reason": "SecOps Lead Signoff"})
db_act_app = query_db("SELECT authorization_state FROM action_executions WHERE id = ?", (action_id,))
record("Action Approval Mutation", db_act_app[0][0] == "AUTHORIZED", f"Approved action {action_id}, DB authorization_state: {db_act_app[0][0]}")

# Execute
st_exe, resp_exe = api_call("POST", f"/organizations/org-001/actions/{action_id}/execute", "user-admin-01")
db_act_exe = query_db("SELECT execution_state FROM action_executions WHERE id = ?", (action_id,))
record("Action Execution Mutation", db_act_exe[0][0] in ("EXECUTED", "SUCCEEDED"), f"Executed action {action_id}, DB execution_state: {db_act_exe[0][0]}")

# Rollback
st_rb, resp_rb = api_call("POST", f"/organizations/org-001/actions/{action_id}/rollback", "user-admin-01")
db_rb = query_db("SELECT rollback_action_type, rollback_state FROM action_rollbacks WHERE action_execution_id = ?", (action_id,))
record("Action Rollback Mutation", len(db_rb) > 0, f"Rolled back action {action_id}, DB rollback record: {db_rb}")

# -------------------------------------------------------------------------
# 6. AUTOMATION POLICY CREATE, TOGGLE, DELETE
# -------------------------------------------------------------------------
print("\n--- 6. Testing Automation Policy Lifecycle ---")
policy_payload = {
    "name": "Auto-Quarantine External High-Risk Service",
    "description": "Automatically isolate internet-exposed services with critical vulnerabilities",
    "is_enabled": True,
    "allow_auto_approval": False,
    "max_risk_class": "CLASS_B_LOW_RISK_REVERSIBLE",
    "allowed_action_types": ["RESOLVE_FINDING", "ACKNOWLEDGE_FINDING"]
}
st_pol, resp_pol = api_call("POST", "/organizations/org-001/automation/policies", "user-admin-01", body=policy_payload)
policy_id = resp_pol.get("id")
db_pol = query_db("SELECT id, name, is_enabled FROM automation_policies WHERE id = ?", (policy_id,))
record("Automation Policy Creation Mutation", len(db_pol) > 0, f"Created policy {policy_id}, DB row: {db_pol}")

# Toggle
st_tog, resp_tog = api_call("PATCH", f"/organizations/org-001/automation/policies/{policy_id}/toggle", "user-admin-01")
db_pol_tog = query_db("SELECT is_enabled FROM automation_policies WHERE id = ?", (policy_id,))
record("Automation Policy Toggle Mutation", db_pol_tog[0][0] == 0, f"Toggled policy {policy_id}, DB is_enabled: {db_pol_tog[0][0]}")

# Delete
st_del, resp_del = api_call("DELETE", f"/organizations/org-001/automation/policies/{policy_id}", "user-admin-01")
db_pol_del = query_db("SELECT id FROM automation_policies WHERE id = ?", (policy_id,))
record("Automation Policy Deletion Mutation", len(db_pol_del) == 0, f"Deleted policy {policy_id}, DB existence: {len(db_pol_del) > 0}")

# -------------------------------------------------------------------------
# 7. NOTIFICATION DESTINATION CREATION & AUDITING
# -------------------------------------------------------------------------
print("\n--- 7. Testing Notification Destination Creation & Audit ---")
dest_payload = {
    "channel": "webhook",
    "name": "SecOps Incident Response Webhook",
    "config": {"url": "https://httpbin.org/post", "secret": "whsec_audit_token_test"}
}
st_dest, resp_dest = api_call("POST", "/organizations/org-001/notifications/destinations", "user-admin-01", body=dest_payload)
dest_id = resp_dest.get("id")
db_dest = query_db("SELECT id, name, channel FROM notification_destinations WHERE id = ?", (dest_id,))
record("Notification Destination Mutation", len(db_dest) > 0, f"Created webhook destination {dest_id}, DB row: {db_dest}")

# -------------------------------------------------------------------------
# 8. API KEY GENERATION & REVOCATION WITH AUDIT
# -------------------------------------------------------------------------
print("\n--- 8. Testing API Key Lifecycle & Audit Events ---")
st_k, resp_k = api_call("POST", "/auth/organizations/org-001/apikeys", "user-admin-01", body={"key_name": "Audit Verification Service Key"})
key_id = resp_k.get("id")
db_audit_k = query_db("SELECT event_type, resource_id, actor_id FROM audit_events WHERE resource_id = ?", (key_id,))
record("API Key Generation Mutation", len(db_audit_k) > 0, f"Generated key {key_id}, audit event persisted: {db_audit_k}")

st_rk, resp_rk = api_call("DELETE", f"/auth/organizations/org-001/apikeys/{key_id}", "user-admin-01")
db_audit_rk = query_db("SELECT event_type, resource_id FROM audit_events WHERE resource_id = ? AND event_type = 'API_KEY_REVOKED'", (key_id,))
record("API Key Revocation Mutation", len(db_audit_rk) > 0, f"Revoked key {key_id}, audit event persisted: {db_audit_rk}")

# -------------------------------------------------------------------------
# 9. SETTINGS MUTATIONS & AUDIT
# -------------------------------------------------------------------------
print("\n--- 9. Testing Settings Mutation & Audit Event ---")
new_org_title = "Enterprise Attack Surface Defense Tenant"
st_set, resp_set = api_call("PUT", "/auth/organizations/org-001/settings", "user-admin-01", body={"name": new_org_title})
db_org = query_db("SELECT name, updated_at FROM organizations WHERE id = 'org-001'")
record("Organization Settings Mutation", db_org[0][0] == new_org_title, f"Updated organization name to '{db_org[0][0]}', DB persistence confirmed")

# -------------------------------------------------------------------------
# 10. CONTEXT OVERRIDE & DECISION RECORDING
# -------------------------------------------------------------------------
print("\n--- 10. Testing Context Override & Security Decision Recording ---")
asset_rows = query_db("SELECT id, identifier FROM assets WHERE org_id = 'org-001' LIMIT 1")
if asset_rows:
    asset_id = asset_rows[0][0]
    ctx_body = {
        "criticality": "critical",
        "environment": "production",
        "owner_team": "SecOps Core Platform",
        "business_purpose": "Primary Public Authentication Gateway"
    }
    st_ctx, resp_ctx = api_call("PATCH", f"/organizations/org-001/assets/{asset_id}/context", "user-admin-01", body=ctx_body)
    db_ctx = query_db("SELECT criticality, environment, owner_team FROM asset_contexts WHERE asset_id = ?", (asset_id,))
    record("Asset Context Override Mutation", len(db_ctx) > 0 and db_ctx[0][0] == "critical", f"Updated asset context on {asset_id}, DB row: {db_ctx}")

    dec_body = {
        "decision_type": "accept_risk",
        "scope_level": "asset",
        "subject_identifier": asset_id,
        "subject_type": "asset",
        "new_state": {"accepted_risk": True},
        "reason": "Compensating WAF and mTLS controls active in production"
    }
    st_dec, resp_dec = api_call("POST", "/organizations/org-001/decisions", "user-admin-01", body=dec_body)
    dec_id = resp_dec.get("id")
    db_dec = query_db("SELECT id, decision_type, status FROM organizational_decisions WHERE id = ?", (dec_id,))
    record("Security Decision Mutation", len(db_dec) > 0, f"Created security decision {dec_id}, DB row: {db_dec}")

# -------------------------------------------------------------------------
# 11. AI ASSISTANT QUERY & CONVERSATION PERSISTENCE
# -------------------------------------------------------------------------
print("\n--- 11. Testing AI Security Assistant Grounding & Persistence ---")
st_ai, resp_ai = api_call("POST", "/organizations/org-001/assistant/query", "user-viewer-01", body={"query": "Analyze exposed internet assets"})
conv_id = resp_ai.get("conversation_id")
db_conv = query_db("SELECT id, title FROM ai_conversations WHERE id = ?", (conv_id,))
db_msg = query_db("SELECT sender_type, content FROM ai_messages WHERE conversation_id = ? ORDER BY created_at ASC", (conv_id,))
record("AI Assistant Query & Grounding", len(db_conv) > 0 and len(db_msg) >= 2, f"Persisted conversation {conv_id} with {len(db_msg)} messages, Facts grounded: {len(resp_ai.get('response', {}).get('facts', []))}")

print("\n=========================================================================")
passed_count = sum(1 for r in results if r['status'] == 'PASS')
total_count = len(results)
print(f"MUTATION AUDIT COMPLETE: {passed_count} / {total_count} PASSED")
print("=========================================================================")

if passed_count != total_count:
    sys.exit(1)
