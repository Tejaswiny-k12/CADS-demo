"""CADS Security Operations Center dashboard."""

import os
import sqlite3
import subprocess
import sys
import time
from html import escape

import pandas as pd
import streamlit as st

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "cads.db")
SIMULATOR = os.path.join(BASE_DIR, "simulator", "simulator.py")
REFRESH_INTERVAL = 5
IST_TZ = "Asia/Kolkata"

st.set_page_config(page_title="CADS Security Operations Center", page_icon="C", layout="wide", initial_sidebar_state="collapsed")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
:root{--bg0:#0a0d13;--bg1:#0f131b;--bg2:#141922;--border:#232a36;--soft:#1a202b;--hi:#e7eaf0;--mid:#a4adbc;--lo:#5f6a7d;--teal:#2dd4bf;--tdim:#0f4640;--amber:#f0a94e;--adim:#4a3618;--red:#f0546b;--rdim:#4a1622}
*{box-sizing:border-box}html,body,[data-testid="stAppViewContainer"],[data-testid="stHeader"]{background:var(--bg0);color:var(--hi);font-family:Inter,sans-serif}[data-testid="stAppViewContainer"]{background:radial-gradient(900px 360px at 12% -14%,#182333 0%,transparent 64%),var(--bg0)}[data-testid="stHeader"],[data-testid="stToolbar"]{display:none}section.main>div{max-width:1360px;padding-top:1.2rem}h1,h2,h3,p,label,[data-testid="stMarkdownContainer"]{color:var(--hi)!important}h1,h2,h3{font-family:'Space Grotesk',sans-serif}h1{font-size:1.4rem;margin-bottom:0}h2{font-size:1rem}h3{font-size:.86rem}[data-testid="stMetric"]{background:var(--bg1);border:1px solid var(--border);border-radius:10px;padding:13px 15px}[data-testid="stMetricLabel"]{color:var(--lo)!important;font:11px 'IBM Plex Mono',monospace;text-transform:uppercase;letter-spacing:.05em}[data-testid="stMetricValue"]{color:var(--hi)!important;font-family:'Space Grotesk',sans-serif}[data-baseweb="tab"]{color:var(--lo)!important;font-family:'IBM Plex Mono',monospace}[data-baseweb="tab"][aria-selected="true"]{color:var(--teal)!important;border-bottom:2px solid var(--teal)!important}[data-testid="stDataFrame"]{border:1px solid var(--border)}
.soc-header{display:flex;justify-content:space-between;align-items:center;gap:18px;padding:2px 0 18px;border-bottom:1px solid var(--border);margin-bottom:20px}.brand{display:flex;align-items:center;gap:12px}.brand-mark{width:35px;height:35px;border:1px solid var(--teal);border-radius:8px;display:flex;align-items:center;justify-content:center;color:var(--teal);font:700 15px 'Space Grotesk',sans-serif}.brand-title{font:600 16px 'Space Grotesk',sans-serif}.brand-sub{color:var(--lo);font:11px 'IBM Plex Mono',monospace;margin-top:2px}.live-pill{color:var(--teal);background:var(--tdim);border:1px solid #146357;padding:5px 10px;border-radius:20px;font:11px 'IBM Plex Mono',monospace}.live-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--teal);margin-right:6px}.section-label{color:var(--lo);display:flex;align-items:center;gap:8px;font:11px 'IBM Plex Mono',monospace;letter-spacing:1px;text-transform:uppercase;margin:16px 0 10px}.section-label:after{content:'';height:1px;flex:1;background:var(--soft)}.panel{background:var(--bg1);border:1px solid var(--border);border-radius:10px;padding:16px 18px;margin-bottom:16px}.panel-title{font:600 14px 'Space Grotesk',sans-serif;margin-bottom:13px}.note{color:var(--lo);font:11px 'IBM Plex Mono',monospace}.gate-pass{color:var(--teal)}.gate-fail{color:var(--red)}.gate-warn{color:var(--amber)}button{font-family:'IBM Plex Mono',monospace!important}
.html-table-wrap{overflow-x:auto}.html-table-wrap.scroll-log{max-height:280px;overflow-y:auto}.html-table-wrap.scroll-log .soc-table thead th{position:sticky;top:0;background:var(--bg1);z-index:1}.soc-table{width:100%;border-collapse:collapse;font:12px 'IBM Plex Mono',monospace;color:var(--mid)}.soc-table th{text-align:left;color:var(--lo);font:10px 'IBM Plex Mono',monospace;letter-spacing:.6px;text-transform:uppercase;font-weight:500;padding:0 10px 10px;border-bottom:1px solid var(--soft);white-space:nowrap}.soc-table td{padding:10px;border-bottom:1px solid var(--soft);white-space:nowrap}.soc-table tr:last-child td{border-bottom:0}.soc-table td.hi{color:var(--hi)}.soc-table td.threat{color:var(--red)!important}.badge{display:inline-block;border-radius:20px;padding:3px 9px;font:10px 'IBM Plex Mono',monospace}.badge.ok{background:var(--tdim);color:var(--teal)}.badge.crit{background:var(--rdim);color:#ff8fa0}.badge.warn{background:var(--adim);color:#ffcf8a}.empty-state{padding:18px 4px;text-align:center;border:1px dashed var(--border);border-radius:8px;color:var(--lo);font:12px 'IBM Plex Mono',monospace}
</style>
""", unsafe_allow_html=True)


def query(sql, params=()):
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        return pd.read_sql_query(sql, conn, params=params)


def get_columns(table_name):
    if not os.path.exists(DB_PATH):
        return set()
    with sqlite3.connect(DB_PATH) as conn:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})")}


def to_ist_text(series):
    if series.empty:
        return series
    return pd.to_datetime(series, errors="coerce", utc=True).dt.tz_convert(IST_TZ).dt.strftime("%Y-%m-%d %H:%M:%S IST")


def pct(num, den):
    return 0.0 if den == 0 else num * 100.0 / den


def safe_quantile(series, value):
    numeric = pd.to_numeric(series, errors="coerce").dropna()
    return None if numeric.empty else float(numeric.quantile(value))


def compute_metrics(packets):
    if packets.empty:
        return {"accuracy":0,"precision":0,"recall":0,"f1":0,"fpr":0,"tp":0,"fp":0,"tn":0,"fn":0}
    attack = packets["attack_type"].fillna("NONE") != "NONE"
    rejected = packets["gate1_pass"] == 0
    tp, fp, tn, fn = int((attack & rejected).sum()), int((~attack & rejected).sum()), int((~attack & ~rejected).sum()), int((attack & ~rejected).sum())
    precision, recall = pct(tp, tp + fp), pct(tp, tp + fn)
    return {"accuracy":pct(tp + tn, len(packets)),"precision":precision,"recall":recall,"f1":0 if precision + recall == 0 else 2 * precision * recall / (precision + recall),"fpr":pct(fp, fp + tn),"tp":tp,"fp":fp,"tn":tn,"fn":fn}


def load_data():
    packet_columns = get_columns("packets")
    optional = [c for c in ["check_csm", "check_mba", "verification_latency_ms", "end_to_end_latency_ms"] if c in packet_columns]
    packet_select = ["id","timestamp","device_id","device_name","gate1_pass","reject_reason","check_registered","check_dbi_signature","check_ttl","check_hash","check_popc","attack_type","ttl_remaining","heart_rate","body_temp","battery_level","signal_strength"] + optional
    frames = [
        query(f"SELECT {', '.join(packet_select)} FROM packets ORDER BY id DESC LIMIT 2000"),
        query("SELECT id,timestamp,device_id,device_name,severity,cause,detail,acknowledged FROM alerts ORDER BY id DESC LIMIT 600"),
        query("SELECT device_id,device_name,status,threat_score,packets_sent,packets_rejected,last_seen FROM devices ORDER BY threat_score DESC"),
        query("SELECT id,timestamp,device_name,target_host,target_port,blocked,reason FROM bce_events ORDER BY id DESC LIMIT 300"),
        query("SELECT device_id,gate_name,result,timestamp,session_key_id,reason FROM gate2_auth_logs ORDER BY id DESC LIMIT 300"),
        query("SELECT device_id,session_id,gate_number,gate_name,result,event_time,decision_time,reason FROM gate_events ORDER BY id DESC LIMIT 500"),
        query("SELECT device_id,device_type,firmware_version,last_patch_date,trustzone_attestation,certificate_validity,enrollment_status FROM device_posture"),
        query("SELECT device_id,score,recorded_at,deviation FROM behavioral_scores ORDER BY id DESC LIMIT 300"),
        query("SELECT device_id,event_type,broker,tls_result,topic,observed_at,detail FROM network_telemetry ORDER BY id DESC LIMIT 300"),
        query("SELECT device_id,confirmation_hash,block_timestamp,source FROM audit_trail ORDER BY id DESC LIMIT 300"),
    ]
    for frame, column in zip(frames, ["timestamp","timestamp","last_seen","timestamp","timestamp","event_time",None,"recorded_at","observed_at","block_timestamp"]):
        if not frame.empty and column:
            frame[f"{column}_ist"] = to_ist_text(frame[column])
    if not frames[1].empty:
        frames[1]["status"] = frames[1]["acknowledged"].map({1:"ACKNOWLEDGED",0:"OPEN"})
    if frames[7].empty and not frames[4].empty:
        derived = frames[4][["device_id", "result", "timestamp", "timestamp_ist", "reason"]].copy()
        derived["score"] = derived.apply(
            lambda row: 100.0 if row["result"] == "PASS" else 0.0 if row["reason"] == "MBA_ANOMALY" else 25.0,
            axis=1,
        )
        derived["recorded_at"] = derived["timestamp"]
        derived["recorded_at_ist"] = derived["timestamp_ist"]
        derived["deviation"] = derived["reason"].fillna("NONE").map(
            lambda reason: "MBA deviation" if reason == "MBA_ANOMALY" else reason
        )
        derived["source"] = "Derived from Gate-2 decisions"
        frames[7] = derived[["device_id", "score", "recorded_at", "recorded_at_ist", "deviation", "source"]]
    return frames


def run_simulation(mode, count):
    try:
        result = subprocess.run([sys.executable, SIMULATOR, "--mode", mode, "--count", str(count)], cwd=BASE_DIR, capture_output=True, text=True, timeout=45, check=False)
        return result.returncode, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "Simulation timed out after 45 seconds."


def short_id(value):
    value = str(value or "")
    return f"{value[:8]}...{value[-6:]}" if len(value) > 16 else value


def badge(value):
    text = str(value or "-")
    lowered = text.lower()
    kind = "ok" if lowered in {"pass", "success", "active", "allow", "allowed"} else "crit" if lowered in {"fail", "failed", "open", "blocked", "critical"} else "warn" if lowered in {"warning", "not recorded", "not wired"} else ""
    return f"<span class='badge {kind}'>{escape(text)}</span>" if kind else escape(text)


def html_table(headers, rows, badge_columns=(), threat_columns=(), scroll=False):
    header_html = "".join(f"<th>{escape(str(header))}</th>" for header in headers)
    body = []
    for row in rows:
        cells = []
        for index, value in enumerate(row):
            rendered = badge(value) if index in badge_columns else escape(str(value if value not in (None, "") else "-"))
            classes = []
            if index == 0:
                classes.append("hi")
            if index in threat_columns and ("evil" in str(value).lower() or "blocked" in str(value).lower()):
                classes.append("threat")
            cells.append(f"<td class='{' '.join(classes)}'>{rendered}</td>")
        body.append(f"<tr>{''.join(cells)}</tr>")
    if not body:
        body.append(f"<tr><td colspan='{len(headers)}'><div class='empty-state'>No records available</div></td></tr>")
    wrapper_class = "html-table-wrap scroll-log" if scroll else "html-table-wrap"
    return f"<div class='{wrapper_class}'><table class='soc-table'><thead><tr>{header_html}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"


def main():
    packets, alerts, devices, bce, gate2, gate_events, posture, scores, network, audit = load_data()
    metrics = compute_metrics(packets)
    p95 = safe_quantile(packets["verification_latency_ms"], .95) if "verification_latency_ms" in packets else None
    open_incidents = alerts[alerts["acknowledged"] == 0] if not alerts.empty else alerts
    open_gate1 = open_incidents[open_incidents["cause"].isin({"CSM_INVALID", "DEVICE_NOT_REGISTERED", "DEVICE_QUARANTINED", "DBI_INVALID", "EXPIRED_TTL", "HASH_MISMATCH", "POPC_MISSING", "POPC_MALFORMED", "MBA_ANOMALY"})] if not open_incidents.empty else open_incidents
    st.markdown(f"<div class='soc-header'><div class='brand'><div class='brand-mark'>C</div><div><div class='brand-title'>CADS Security Operations Center</div><div class='brand-sub'>Credential-Agnostic Data Sovereignty · IoMT Trust Pipeline</div></div></div><span class='live-pill'><span class='live-dot'></span>LIVE · {time.strftime('%H:%M:%S IST')}</span></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>Operations summary</div>", unsafe_allow_html=True)
    kpis = st.columns(5)
    kpis[0].metric("Active devices", len(devices)); kpis[1].metric("Open incidents", len(open_incidents)); kpis[2].metric("Detection recall", f"{metrics['recall']:.1f}%"); kpis[3].metric("False positive rate", f"{metrics['fpr']:.1f}%"); kpis[4].metric("Verify latency p95", "N/A" if p95 is None else f"{p95:.2f} ms")
    tab_ops, tab_eval, tab_live = st.tabs(["SOC Operations", "CADS Evaluation", "Live Simulations"])

    with tab_ops:
        st.markdown("<div class='section-label'>Gate pipeline flow</div>", unsafe_allow_html=True)
        latest_packet = packets.iloc[0] if not packets.empty else None
        latest_gate2 = gate2.iloc[0] if not gate2.empty else None
        gate1_state = f"FAIL · {len(open_gate1)} open" if not open_gate1.empty else "PASS"
        ttl_state = "PASS" if latest_packet is not None and bool(latest_packet["check_ttl"]) else "FAIL" if latest_packet is not None else "NOT RECORDED"
        popc_state = "PASS" if latest_packet is not None and bool(latest_packet["check_popc"]) else "FAIL" if latest_packet is not None else "NOT RECORDED"
        trust_state = "PASS" if latest_packet is not None and bool(latest_packet["gate1_pass"]) and latest_gate2 is not None and latest_gate2["result"] == "PASS" else "FAIL" if latest_packet is not None else "NOT RECORDED"
        values = [("Gate 1","Identity / packet", gate1_state if latest_packet is not None or not open_gate1.empty else "NOT RECORDED"),("Gate 2","Challenge / MBA",latest_gate2["result"] if latest_gate2 is not None else "NOT RECORDED"),("Gate 3","C-TTL",ttl_state),("Gate 4","PoPC / path",popc_state),("Gate 5","Trust decision",trust_state)]
        columns = st.columns([1,.08,1,.08,1,.08,1,.08,1])
        for index, (number, name, result) in enumerate(values):
            css = "gate-pass" if result == "PASS" else "gate-fail" if result.startswith("FAIL") else "gate-warn" if result == "NOT RECORDED" else "note"
            columns[index * 2].markdown(f"<div class='panel'><div class='note'>{number}</div><h3>{name}</h3><strong class='{css}'>{result}</strong></div>", unsafe_allow_html=True)
            if index < 4:
                columns[index * 2 + 1].markdown("<div style='text-align:center;padding-top:35px;color:#5f6a7d;font-size:20px'>→</div>", unsafe_allow_html=True)
        st.caption("Gate 1 and Gate 2 emit live evidence. Gates 3-5 activate when their services publish to gate_events.")
        identity, crypto = st.columns(2)
        with identity:
            st.markdown("<div class='panel'><div class='panel-title'>Device identity and posture</div>", unsafe_allow_html=True)
            if devices.empty: st.info("No enrolled devices.")
            else:
                view = devices.rename(columns={"device_name":"device","last_seen_ist":"last_seen"})
                if not posture.empty: view = view.merge(posture, on="device_id", how="left")
                for column in ["device_type","firmware_version","last_patch_date","trustzone_attestation","certificate_validity","enrollment_status"]:
                    if column not in view: view[column] = "Not recorded"
                    view[column] = view[column].fillna("Not recorded")
                missing_enrollment = view["enrollment_status"].eq("Not recorded")
                view.loc[missing_enrollment, "enrollment_status"] = view.loc[missing_enrollment, "status"]
                rows = view[["device","device_id","enrollment_status","device_type"]].head(20).values.tolist()
                st.markdown(html_table(["Device", "Device ID", "Enrollment", "DBI baseline"], [(row[0], short_id(row[1]), row[2], "Not established") for row in rows], badge_columns=(2,), scroll=True), unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        with crypto:
            st.markdown("<div class='panel'><div class='panel-title'>Crypto session and key exchange</div>", unsafe_allow_html=True)
            if gate2.empty: st.info("No Gate-2 sessions authenticated.")
            else:
                view = gate2.copy(); view["device_id"] = view["device_id"].map(short_id); view["ECDH"] = view["result"].map({"PASS":"Success","FAIL":"Failed"}).fillna("Unknown"); view["session_key_id"] = view["session_key_id"].fillna("-").map(short_id)
                pass_count = int((gate2["result"] == "PASS").sum())
                st.markdown(f"<div class='note'>Pass rate: {pass_count}/{len(gate2)} · showing latest 7 decisions</div>", unsafe_allow_html=True)
                rows = view[["device_id","ECDH","result","session_key_id"]].head(7).values.tolist()
                st.markdown(html_table(["Device ID", "ECDH", "Result", "Session key"], [(row[0], row[1], row[2], row[3]) for row in rows], badge_columns=(2,), scroll=True), unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        incidents, network_panel = st.columns(2)
        with incidents:
            st.markdown("<div class='panel'><div class='panel-title'>Incidents · aggregated</div>", unsafe_allow_html=True)
            if alerts.empty: st.info("No incidents recorded.")
            else:
                view = alerts.groupby(["cause","severity"], as_index=False).agg(count=("id","count"),unique_devices=("device_id","nunique"),last_seen=("timestamp_ist","max"))
                open_by_cause = open_incidents.groupby("cause").size().to_dict() if not open_incidents.empty else {}
                view["status"] = view["cause"].map(lambda cause: f"Open ({open_by_cause.get(cause, 0)})" if open_by_cause.get(cause, 0) else "Resolved")
                rows = view.sort_values("count", ascending=False)[["cause","severity","count","unique_devices","last_seen","status"]].head(30).values.tolist()
                st.markdown(html_table(["Cause", "Severity", "Count", "Unique devices", "Last seen (IST)", "Status"], rows, badge_columns=(1, 5), scroll=True), unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        with network_panel:
            st.markdown("<div class='panel'><div class='panel-title'>Network telemetry</div>", unsafe_allow_html=True)
            if network.empty: st.info("No MQTT, TLS, or topic telemetry recorded.")
            else:
                rows = network[["observed_at_ist","event_type","broker"]].values.tolist()
                st.markdown(html_table(["Observed (IST)", "Event", "Broker"], rows, threat_columns=(2,), scroll=True), unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        score_panel, audit_panel = st.columns(2)
        with score_panel:
            st.markdown("<div class='panel'><div class='panel-title'>Behavioral score and deviations</div>", unsafe_allow_html=True)
            if scores.empty: st.info("No DBI/MBA score history recorded.")
            else:
                score_note = scores["source"].iloc[0] if "source" in scores else ""
                if score_note: st.caption(score_note)
                score_view = scores.copy()
                score_view["score"] = pd.to_numeric(score_view["score"], errors="coerce")
                score_view = score_view.dropna(subset=["score"])
                if score_view.empty:
                    st.info("Behavioral score records contain no numeric values.")
                else:
                    st.line_chart(score_view.set_index("recorded_at_ist")["score"])
                    st.markdown(html_table(["Device ID", "Score", "Recorded (IST)", "Deviation"], score_view[["device_id","score","recorded_at_ist","deviation"]].head(25).values.tolist()), unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
        with audit_panel:
            st.markdown("<div class='panel'><div class='panel-title'>BCE audit trail</div>", unsafe_allow_html=True)
            if audit.empty: st.info("No ledger confirmation records yet. BCE block/allow records remain in the simulator evidence.")
            else: st.markdown(html_table(["Device ID", "Confirmation hash", "Block timestamp", "Source"], audit[["device_id","confirmation_hash","block_timestamp_ist","source"]].values.tolist()), unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    with tab_eval:
        st.markdown("<div class='section-label'>CADS Evaluation</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'><div class='panel-title'>Reviewer evidence summary</div><div class='note'>Metrics are computed from persisted packet and Gate-2 evidence. Empty sources are N/A.</div></div>", unsafe_allow_html=True)
        left, right = st.columns(2)
        with left:
            st.markdown("<div class='panel'><div class='panel-title'>Confusion matrix</div>", unsafe_allow_html=True); st.dataframe(pd.DataFrame([[metrics["tp"],metrics["fn"]],[metrics["fp"],metrics["tn"]],], index=["Actual attack","Actual benign"], columns=["Predicted attack","Predicted benign"]), use_container_width=True); st.markdown("</div>", unsafe_allow_html=True)
        with right:
            st.markdown("<div class='panel'><div class='panel-title'>Latency and overhead</div>", unsafe_allow_html=True)
            rows = []
            for label, column, quantile in [("Gate 1 verification mean","verification_latency_ms",None),("Gate 1 verification p95","verification_latency_ms",.95),("End-to-end mean","end_to_end_latency_ms",None)]:
                if column in packets and not packets.empty:
                    numeric = pd.to_numeric(packets[column], errors="coerce").dropna(); value = numeric.quantile(quantile) if quantile else numeric.mean(); rows.append({"Metric":label,"Value (ms)":round(float(value),3) if not numeric.empty else "N/A"})
                else: rows.append({"Metric":label,"Value (ms)":"N/A"})
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True); st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'><div class='panel-title'>Six-algorithm health and evidence contract</div>", unsafe_allow_html=True)
        coverage = []
        if not packets.empty:
            for label, column in [("DBI","check_dbi_signature"),("C-TTL","check_ttl"),("PoPC","check_popc"),("CSM","check_csm"),("MBA","check_mba")]: coverage.append({"Algorithm":label,"Evidence":f"packets.{column}","Pass rate":f"{pct((packets[column] == 1).sum(),len(packets)):.1f}%" if column in packets else "N/A"})
        coverage += [{"Algorithm":"BCE","Evidence":"bce_events.blocked","Pass rate":f"{pct((bce['blocked'] == 1).sum(),len(bce)):.1f}%" if not bce.empty else "N/A"}]
        st.dataframe(pd.DataFrame(coverage), use_container_width=True, hide_index=True); st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'><div class='panel-title'>Gate-2 authentication health</div>", unsafe_allow_html=True)
        gate2_rate = f"{pct((gate2['result'] == 'PASS').sum(), len(gate2)):.1f}%" if not gate2.empty else "N/A"
        st.markdown(html_table(["Protocol", "Evidence", "Pass rate", "Latest state"], [["Gate-2 ECDSA/ECDH/MBA", "gate2_auth_logs.result", gate2_rate, gate2.iloc[0]["result"] if not gate2.empty else "N/A"]], badge_columns=(3,)), unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'><div class='panel-title'>Reviewer interpretation</div><ul><li>Attack samples are labeled by simulator mode and evaluated against Gate-1 rejection.</li><li>Gate-2 separately measures nonce replay, response timing, signature validity, ECDH session creation, and MBA behavior.</li><li>Gates 3-5 are not counted as passing until signed gate_events records exist.</li><li>Session key material is never rendered; only its ID is displayed.</li></ul></div>", unsafe_allow_html=True)

    with tab_live:
        st.markdown("<div class='section-label'>Live simulations and attack stimulation</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'><div class='panel-title'>Run a real CADS scenario</div><div class='note'>Each action invokes simulator.py, writes SQLite evidence, and refreshes the page.</div>", unsafe_allow_html=True)
        scenario = st.selectbox("Scenario", ["normal","tamper","replay","bad_sig","anomaly","c2","gate2_normal","gate2_bad_sig","gate2_replay","gate2_stale","gate2_mba"], format_func=lambda value: value.replace("_"," ").title())
        count = st.number_input("Packet count", min_value=1, max_value=50, value=1, step=1, disabled=scenario.startswith("gate2_") or scenario == "c2")
        if st.button("Run simulation", type="primary"):
            code, output = run_simulation(scenario, int(count)); st.session_state["last_simulation"] = output; st.session_state["last_simulation_code"] = code; st.rerun()
        if st.session_state.get("last_simulation"):
            st.markdown(f"**Last run: {'PASS' if st.session_state.get('last_simulation_code') == 0 else 'FAILED'}**"); st.code(st.session_state["last_simulation"])
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'><div class='panel-title'>Recent Gate-2 decisions</div>", unsafe_allow_html=True)
        if gate2.empty: st.info("No Gate-2 decisions recorded.")
        else: st.dataframe(gate2[["device_id","result","timestamp_ist","session_key_id","reason"]].head(50), use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(f"<div class='note'>Last ingestion: {packets.iloc[0]['timestamp_ist'] if not packets.empty else 'N/A'} · Source: SQLite evidence store · Refresh interval: {REFRESH_INTERVAL}s</div>", unsafe_allow_html=True)
    time.sleep(REFRESH_INTERVAL); st.rerun()


if __name__ == "__main__":
    main()