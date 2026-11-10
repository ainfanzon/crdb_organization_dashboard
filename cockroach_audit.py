import os
import json
import requests
import datetime
import pandas as pd
import streamlit as st
import plotly.express as px

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="CockroachDB Cloud Audit Explorer",
    page_icon="cc.png",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# Session State Initialization (for Reset Button)
# ---------------------------------------------------------
DEFAULT_VALUES = {
    "record_limit": 1200,
    "time_preset": "Latest Events (Real-Time)",
    "custom_start_date": datetime.date.today() - datetime.timedelta(days=1),
    "custom_start_time": datetime.time(0, 0),
    "custom_end_date": datetime.date.today(),
    "custom_end_time": datetime.time(23, 59),
    "category_filter": [],
    "source_filter": [],
    "actor_filter": [],
    "cluster_filter": [],
    "only_flagged": False,
    "search_query": "",
}

for key, val in DEFAULT_VALUES.items():
    if key not in st.session_state:
        st.session_state[key] = val

def reset_all_filters():
    for k, v in DEFAULT_VALUES.items():
        st.session_state[k] = v
    st.cache_data.clear()

# ---------------------------------------------------------
# Action Categorization & Risk Rules
# ---------------------------------------------------------
CRITICAL_ACTIONS = {
    "DELETE_CLUSTER",
    "ASSIGN_USER_ROLE",
    "ADD_USER_TO_ROLE",
    "REMOVE_USER_FROM_ROLE",
    "DELETE_USER_FROM_ORGANIZATION",
    "ADD_IP_ALLOWLIST",
    "DELETE_IP_ALLOWLIST",
    "CREATE_SERVICE_ACCOUNT",
    "DELETE_SERVICE_ACCOUNT",
    "CREATE_API_KEY",
    "DELETE_API_KEY",
    "REVOKE_CMEK",
    "ENABLE_CLOUD_ORG_SSO",
    "DELETE_SQL_USER",
}

def clean_action_name(action: str) -> str:
    if not action:
        return "Unknown"
    return action.replace("AUDIT_LOG_ACTION_", "").replace("_", " ").title()

def clean_source_name(source: str) -> str:
    if not source:
        return "Unknown"
    return source.replace("AUDIT_LOG_SOURCE_", "").replace("_", " ")

def categorize_action(raw_action: str) -> str:
    act = (raw_action or "").replace("AUDIT_LOG_ACTION_", "")
    if any(k in act for k in ["ROLE", "INVITE", "SSO", "AUTHENTICATION", "GROUP"]):
        return "Access & RBAC"
    elif any(k in act for k in ["ALLOWLIST", "VPC", "PRIVATE_LINK", "EGRESS"]):
        return "Network & Security"
    elif any(k in act for k in ["CLUSTER", "MAINTENANCE", "CMEK"]):
        return "Cluster Lifecycle"
    elif any(k in act for k in ["SERVICE_ACCOUNT", "API_KEY", "USER_LOGIN", "JWT"]):
        return "Credentials & Auth"
    elif any(k in act for k in ["SQL_USER"]):
        return "SQL Users"
    else:
        return "General Operations"

# ---------------------------------------------------------
# Cloud API Data Fetchers
# ---------------------------------------------------------
@st.cache_data(ttl=120, show_spinner=False)
def fetch_audit_logs(
    api_key: str, 
    max_records: int, 
    version: str, 
    starting_from_ts: str = None, 
    stop_before_ts: str = None
) -> tuple[list, bool]:
    url = "https://cockroachlabs.cloud/api/v1/auditlogevents"
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Cc-Version": version,
    }
    
    all_entries = []
    next_start = starting_from_ts
    reached_target_start = False
    
    stop_dt = None
    if stop_before_ts:
        stop_dt = pd.to_datetime(stop_before_ts)
        if not stop_dt.tzinfo:
            stop_dt = stop_dt.tz_localize("UTC")
    
    while len(all_entries) < max_records:
        fetch_limit = min(300, max_records - len(all_entries))
        params = {
            "sort_order": "DESC",
            "limit": fetch_limit,
        }
        if next_start:
            params["starting_from"] = next_start
            
        resp = requests.get(url, headers=headers, params=params, timeout=25)
        
        if resp.status_code != 200:
            try:
                err_data = resp.json()
                msg = err_data.get("message", resp.text)
            except Exception:
                msg = resp.text
            raise Exception(f"HTTP {resp.status_code}: {msg}")
            
        data = resp.json()
        entries = data.get("entries", [])
        if not entries:
            reached_target_start = True
            break
            
        all_entries.extend(entries)
        
        # Check boundary against target stop timestamp
        oldest_in_batch = entries[-1].get("created_at") or entries[-1].get("timestamp")
        if oldest_in_batch and stop_dt is not None:
            oldest_dt = pd.to_datetime(oldest_in_batch)
            if not oldest_dt.tzinfo:
                oldest_dt = oldest_dt.tz_localize("UTC")
            if oldest_dt <= stop_dt:
                reached_target_start = True
                break
        
        new_next = data.get("next_starting_from")
        if not new_next or new_next == next_start:
            reached_target_start = True
            break
        next_start = new_next
        
    return all_entries[:max_records], reached_target_start


@st.cache_data(ttl=120, show_spinner=False)
def fetch_cluster_chargebacks(api_key: str, version: str) -> pd.DataFrame:
    url = "https://cockroachlabs.cloud/api/v1/clusters"
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Cc-Version": version,
        "Content-Type": "application/json",
    }
    
    resp = requests.get(url, headers=headers, timeout=25)
    if resp.status_code != 200:
        return pd.DataFrame()
    
    clusters = resp.json().get("clusters", [])
    
    vcpu_rate = 0.05
    storage_rate = 0.0003
    records = []

    for cluster in clusters:
        if cluster.get("state") != "CREATED":
            continue
            
        config = cluster.get("config", {})
        virtual_cfg = config.get("virtual", {}) or {}
        dedicated_cfg = config.get("dedicated", {}) or {}
        host_cfg = config.get("host", {}) or {}
        labels = cluster.get("labels", {}) or {}

        # Extract vCPUs
        vcpus = (
            virtual_cfg.get("virtual_cpu_burst_limit") or
            dedicated_cfg.get("num_virtual_cpus") or
            host_cfg.get("num_virtual_cpus") or 0
        )
        
        # Extract storage allocation in GiB
        storage_gib = (
            dedicated_cfg.get("storage_gib") or
            host_cfg.get("storage_gib") or 0
        )

        # Compute hourly costs
        hourly_compute = round(vcpus * vcpu_rate, 4)
        hourly_storage = round(storage_gib * storage_rate, 4)
        total_hourly = round(hourly_compute + hourly_storage, 4)

        records.append({
            "tenant_cluster_name": cluster.get("name"),
            "cluster_id": cluster.get("id"),
            "workspace_id": virtual_cfg.get("workspace_id", "N/A"),
            "environment": labels.get("environment", "production"),
            "cost_center": labels.get("cost_center", "unassigned"),
            "allocated_vcpus": vcpus,
            "allocated_storage_gib": storage_gib,
            "hourly_compute_cost_usd": hourly_compute,
            "hourly_storage_cost_usd": hourly_storage,
            "total_hourly_chargeback_usd": total_hourly,
        })

    return pd.DataFrame(records)

# ---------------------------------------------------------
# Sidebar Controls & Settings
# ---------------------------------------------------------
with st.sidebar:
    st.image("https://www.cockroachlabs.com/img/crl-logo-cockroach-labs.svg", width=220)
    st.title("Audit Settings")
    
    default_key = os.getenv("CC_API_KEY", "")
    api_key = st.text_input(
        "API Secret Key",
        value=default_key,
        type="password",
        help="Service Account Secret Key with Org Admin permissions.",
    )
    
    default_version = os.getenv("CC_VERSION", "2026-09-15")
    api_version = st.text_input(
        "Cc-Version",
        value=default_version,
        help="CockroachDB Cloud API version date (e.g. 2026-09-15).",
    )
    
    st.select_slider(
        "Max Safety Cap (Records)",
        options=[300, 600, 1200, 2400, 5000, 10000],
        key="record_limit",
        help="Maximum total records the API will page through.",
    )
    
    st.markdown("---")
    st.subheader("Investigation Scope")
    
    st.selectbox(
        "Select Time Scope",
        options=["Latest Events (Real-Time)", "Last 24 Hours", "Last 7 Days", "Custom Incident Window"],
        key="time_preset",
    )
    
    api_starting_from = None
    api_stop_before = None
    full_target_start_dt = None
    full_target_end_dt = None
    
    if st.session_state["time_preset"] == "Custom Incident Window":
        st.markdown("**Start of Window (UTC):**")
        scol1, scol2 = st.columns([1.3, 1])
        with scol1:
            st.date_input("Start Date", key="custom_start_date")
        with scol2:
            st.time_input("Start Time", key="custom_start_time")
            
        st.markdown("**End of Window (UTC):**")
        ecol1, ecol2 = st.columns([1.3, 1])
        with ecol1:
            st.date_input("End Date", key="custom_end_date")
        with ecol2:
            st.time_input("End Time", key="custom_end_time")
            
        full_target_start_dt = datetime.datetime.combine(
            st.session_state["custom_start_date"], 
            st.session_state["custom_start_time"], 
            tzinfo=datetime.timezone.utc
        )
        full_target_end_dt = datetime.datetime.combine(
            st.session_state["custom_end_date"], 
            st.session_state["custom_end_time"], 
            tzinfo=datetime.timezone.utc
        )
        
        api_starting_from = full_target_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        api_stop_before = full_target_start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    bcol1, bcol2 = st.columns(2)
    with bcol1:
        if st.button("🔄 Fetch Data", width="stretch"):
            st.cache_data.clear()
    with bcol2:
        if st.button("↺ Reset All", width="stretch", on_click=reset_all_filters):
            st.rerun()

# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------
st.title("CockroachDB Cloud Organization Audit Explorer")
st.caption("Centralized visibility into security, infrastructure lifecycle, and access governance.")

if not api_key:
    st.warning("Please supply an API Secret Key in the sidebar or export `CC_API_KEY` in your environment.")
    st.stop()

with st.spinner("Querying and paginating CockroachDB Cloud API..."):
    try:
        raw_events, reached_target_start = fetch_audit_logs(
            api_key, 
            st.session_state["record_limit"], 
            api_version, 
            starting_from_ts=api_starting_from,
            stop_before_ts=api_stop_before
        )
    except Exception as e:
        st.error(f"Failed to fetch logs: {e}")
        st.stop()

if not raw_events:
    st.info("No audit events were returned for this organization.")
    st.stop()

# ---------------------------------------------------------
# Data Processing & Normalization
# ---------------------------------------------------------
df = pd.DataFrame(raw_events)

if "created_at" in df.columns and "timestamp" not in df.columns:
    df["timestamp"] = df["created_at"]
elif "timestamp" not in df.columns:
    df["timestamp"] = None

df["datetime"] = pd.to_datetime(df["timestamp"], errors="coerce")
if df["datetime"].isna().all():
    df["datetime"] = pd.Timestamp.utcnow()

df["time_display"] = df["datetime"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def resolve_actor(row):
    if pd.notna(row.get("user_email")) and str(row.get("user_email")).strip():
        return str(row["user_email"]).strip()
    if pd.notna(row.get("service_account_name")) and str(row.get("service_account_name")).strip():
        return f"SA: {row['service_account_name'].strip()}"
    if pd.notna(row.get("system_actor_name")) and str(row.get("system_actor_name")).strip():
        return f"System: {row['system_actor_name'].strip()}"
    return "Unknown Actor"

df["actor"] = df.apply(resolve_actor, axis=1)

for col in ["id", "action", "cluster_name", "source", "details"]:
    if col not in df.columns:
        df[col] = None

df["action_clean"] = df["action"].apply(clean_action_name)
df["category"] = df["action"].apply(categorize_action)
df["raw_action_short"] = df["action"].fillna("").str.replace("AUDIT_LOG_ACTION_", "", regex=False)
df["is_critical"] = df["raw_action_short"].isin(CRITICAL_ACTIONS)
df["cluster"] = df["cluster_name"].fillna("— (Org Level)")
df["source_type"] = df["source"].apply(clean_source_name)

# Ingestion Metadata
min_ingested_dt = df["datetime"].min()
max_ingested_dt = df["datetime"].max()
ingested_duration = max_ingested_dt - min_ingested_dt
duration_days = ingested_duration.total_seconds() / 86400

# ---------------------------------------------------------
# Sidebar Facet Filters
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("---")
    st.subheader("Filter Ingested Events")
    
    cat_options = [c for c in sorted(df["category"].dropna().unique()) if c]
    st.multiselect("Category", options=cat_options, key="category_filter")
    
    source_options = [s for s in sorted(df["source_type"].dropna().unique()) if s]
    st.multiselect("Source", options=source_options, key="source_filter")
    
    actor_options = [a for a in sorted(df["actor"].dropna().unique()) if a]
    st.multiselect("Actor", options=actor_options, key="actor_filter")
    
    cluster_options = [c for c in sorted(df["cluster"].dropna().unique()) if c]
    st.multiselect("Cluster", options=cluster_options, key="cluster_filter")
    
    st.checkbox("Show Security Critical Only", key="only_flagged")
    st.text_input("Search Details / Actions", placeholder="e.g. admin, allowlist, us-east-1", key="search_query")

# Apply Date-Range Bound locally
filtered_df = df.copy()

if st.session_state["time_preset"] == "Last 24 Hours":
    cutoff = max_ingested_dt - pd.Timedelta(hours=24)
    filtered_df = filtered_df[filtered_df["datetime"] >= cutoff]
elif st.session_state["time_preset"] == "Last 7 Days":
    cutoff = max_ingested_dt - pd.Timedelta(days=7)
    filtered_df = filtered_df[filtered_df["datetime"] >= cutoff]
elif st.session_state["time_preset"] == "Custom Incident Window" and full_target_start_dt and full_target_end_dt:
    s_dt = pd.to_datetime(full_target_start_dt)
    e_dt = pd.to_datetime(full_target_end_dt)
    filtered_df = filtered_df[(filtered_df["datetime"] >= s_dt) & (filtered_df["datetime"] <= e_dt)]

# Apply Facet Filters
if st.session_state["category_filter"]:
    filtered_df = filtered_df[filtered_df["category"].isin(st.session_state["category_filter"])]
if st.session_state["source_filter"]:
    filtered_df = filtered_df[filtered_df["source_type"].isin(st.session_state["source_filter"])]
if st.session_state["actor_filter"]:
    filtered_df = filtered_df[filtered_df["actor"].isin(st.session_state["actor_filter"])]
if st.session_state["cluster_filter"]:
    filtered_df = filtered_df[filtered_df["cluster"].isin(st.session_state["cluster_filter"])]
if st.session_state["only_flagged"]:
    filtered_df = filtered_df[filtered_df["is_critical"] == True]
if st.session_state["search_query"]:
    q = st.session_state["search_query"].lower()
    mask = (
        filtered_df["action_clean"].str.lower().str.contains(q, na=False) |
        filtered_df["actor"].str.lower().str.contains(q, na=False) |
        filtered_df["cluster"].str.lower().str.contains(q, na=False) |
        filtered_df["details"].astype(str).str.lower().str.contains(q, na=False)
    )
    filtered_df = filtered_df[mask]

# ---------------------------------------------------------
# Executive KPI & Ingestion Coverage Row
# ---------------------------------------------------------
col_window, kpi1, kpi2, kpi3, kpi4 = st.columns([2.3, 1, 1, 1, 1])

start_utc = min_ingested_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
stop_utc = max_ingested_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
span_str = f"{duration_days:.1f} days" if duration_days >= 1 else f"{ingested_duration.total_seconds()/3600:.1f} hrs"

if st.session_state["time_preset"] == "Custom Incident Window" and not reached_target_start:
    coverage_badge = "<span style='color: #d9534f; font-weight: 700;'>⚠️ Cap Reached (More data exists)</span>"
else:
    coverage_badge = "<span style='color: #28a745; font-weight: 700;'>✅ Window Fully Covered</span>"

with col_window:
    st.markdown(
        f"""
        <div style="border: 1px solid #dee2e6; border-radius: 8px; padding: 10px 14px; background: #f8f9fa;">
            <div style="display: flex; justify-content: space-between; font-size: 0.78rem; text-transform: uppercase;">
                <span style="color: #495057; font-weight: 700;">📡 Ingested Window ({span_str})</span>
                <span>{coverage_badge}</span>
            </div>
            <div style="font-size: 0.86rem; font-family: monospace; margin-top: 4px;">
                <span style="color: #28a745;">▶</span> <b>From:</b> {start_utc}
            </div>
            <div style="font-size: 0.86rem; font-family: monospace;">
                <span style="color: #dc3545;">■</span> <b>To:&nbsp;&nbsp;&nbsp;</b> {stop_utc}
            </div>
            <div style="font-size: 0.76rem; color: #6c757d; margin-top: 3px;">
                Ingested <b>{len(df):,}</b> events &bull; <b>{len(filtered_df):,}</b> match active filters
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

total_count = len(filtered_df)
crit_count = int(filtered_df["is_critical"].sum())
unique_actors = filtered_df["actor"].nunique()
api_ratio = round((filtered_df["source_type"].str.contains("API|CC API", case=False, na=False)).mean() * 100, 1) if total_count > 0 else 0

kpi1.metric("Matching Events", f"{total_count:,}")
kpi2.metric("Critical Actions", f"{crit_count:,}", delta="Security Review" if crit_count > 0 else "Normal", delta_color="inverse")
kpi3.metric("Unique Actors", f"{unique_actors:,}")
kpi4.metric("Automation Ratio (API)", f"{api_ratio}%")

st.markdown("---")

# Warning if cap stopped the search before reaching start date
if st.session_state["time_preset"] == "Custom Incident Window" and not reached_target_start:
    st.warning(
        f"⚠️ **Safety Cap Reached:** The API stopped at **{start_utc}** after reaching the `{st.session_state['record_limit']:,}` record limit before reaching your requested start time (`{full_target_start_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}`).\n\n"
        f"**Suggested Next Steps:**\n"
        f"1. Narrow the hour/minute window (e.g. check 4–6 hours at a time).\n"
        f"2. Or increase the **Max Safety Cap (Records)** in the sidebar to 5,000 or 10,000."
    )

# ---------------------------------------------------------
# High-Impact Security & Governance Alert Banner
# ---------------------------------------------------------
critical_df = filtered_df[filtered_df["is_critical"] == True]
if not critical_df.empty:
    with st.expander(f"🚨 **High-Impact Governance Events Detected ({len(critical_df)})**", expanded=True):
        st.caption("Actions affecting IAM roles, IP allowlists, cluster deletions, and credentials.")
        preview_table = critical_df[["time_display", "action_clean", "actor", "cluster", "source_type"]]
        st.dataframe(
            preview_table,
            hide_index=True,
            width="stretch",
            height=min(400, max(150, (len(preview_table) + 1) * 38)),
            column_config={
                "time_display": "Timestamp (UTC)",
                "action_clean": "Action",
                "actor": "Actor",
                "cluster": "Cluster Target",
                "source_type": "Source",
            },
        )

# ---------------------------------------------------------
# Interactive Visualizations
# ---------------------------------------------------------
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Event Volume Over Time")
    valid_time_df = filtered_df.dropna(subset=["datetime"]).copy()
    
    if not valid_time_df.empty:
        time_span = valid_time_df["datetime"].max() - valid_time_df["datetime"].min()
        freq = "h" if time_span <= pd.Timedelta(days=2) else "D"
        valid_time_df["time_bucket"] = valid_time_df["datetime"].dt.floor(freq)
        
        timeline_df = (
            valid_time_df.groupby(["time_bucket", "category"])
            .size()
            .reset_index(name="count")
            .sort_values(by="time_bucket")
        )
        
        fig_timeline = px.bar(
            timeline_df,
            x="time_bucket",
            y="count",
            color="category",
            barmode="stack",
            labels={"time_bucket": "Time (UTC)", "count": "Event Count", "category": "Category"},
            template="plotly_white",
            height=320,
        )
        fig_timeline.update_layout(
            margin=dict(l=20, r=20, t=20, b=20),
            legend=dict(orientation="h", y=-0.25, title_text="")
        )
        st.plotly_chart(fig_timeline, width="stretch")
    else:
        st.info("No data matching current filters to plot.")

with col_right:
    st.subheader("Category Distribution")
    if not filtered_df.empty:
        cat_counts = filtered_df["category"].value_counts().reset_index()
        cat_counts.columns = ["category", "count"]
        fig_donut = px.pie(
            cat_counts,
            names="category",
            values="count",
            hole=0.45,
            template="plotly_white",
            height=320,
        )
        fig_donut.update_layout(margin=dict(l=20, r=20, t=20, b=20), showlegend=False)
        st.plotly_chart(fig_donut, width="stretch")
    else:
        st.info("No data.")

st.markdown("---")

# ---------------------------------------------------------
# Tabbed Detail Explorer
# ---------------------------------------------------------
tab_table, tab_actors, tab_inspect, tab_chargeback = st.tabs([
    "📋 Event Log Table", 
    "👤 Actor Breakdown", 
    "🔍 Payload Inspector", 
    "💰 Cluster Chargeback"
])

with tab_table:
    export_cols = ["time_display", "action_clean", "category", "actor", "cluster", "source_type", "id"]
    avail_cols = [c for c in export_cols if c in filtered_df.columns]
    
    st.dataframe(
        filtered_df[avail_cols],
        width="stretch",
        hide_index=True,
        height=400,
        column_config={
            "time_display": "Timestamp (UTC)",
            "action_clean": "Action",
            "category": "Category",
            "actor": "Actor",
            "cluster": "Cluster Target",
            "source_type": "Source",
            "id": "Event ID",
        },
    )
    
    csv_bytes = filtered_df[avail_cols].to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Filtered Audit Logs as CSV",
        data=csv_bytes,
        file_name="cockroach_audit_logs.csv",
        mime="text/csv",
    )

with tab_actors:
    st.subheader("Most Active Actors")
    if not filtered_df.empty:
        top_actors = (
            filtered_df.groupby(["actor", "source_type"])
            .size()
            .reset_index(name="count")
            .sort_values(by="count", ascending=False)
            .head(15)
        )
        fig_actors = px.bar(
            top_actors,
            x="count",
            y="actor",
            color="source_type",
            orientation="h",
            labels={"count": "Actions Taken", "actor": "Actor", "source_type": "Source"},
            template="plotly_white",
            height=380,
        )
        fig_actors.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(fig_actors, width="stretch")
    else:
        st.info("No actor data available.")

with tab_inspect:
    st.subheader("Deep-Dive Event Payload Inspector")
    if not filtered_df.empty:
        event_options = [
            f"{row['time_display']} | {row['action_clean']} | {row['actor']} (ID: {str(row['id'])[:8]}...)"
            for _, row in filtered_df.head(100).iterrows()
        ]
        selected_event_idx = st.selectbox(
            "Select an Event to Inspect Details",
            options=range(len(event_options)),
            format_func=lambda i: event_options[i],
        )
        
        selected_record = filtered_df.iloc[selected_event_idx]
        
        info_col1, info_col2, info_col3 = st.columns(3)
        info_col1.write(f"**Action:** `{selected_record['action']}`")
        info_col2.write(f"**Actor:** `{selected_record['actor']}`")
        info_col3.write(f"**Event ID:** `{selected_record['id']}`")
        
        st.write("**Full Event Payload / Details:**")
        payload_data = selected_record.get("details") or selected_record.get("payload")
        if isinstance(payload_data, str):
            try:
                payload_data = json.loads(payload_data)
            except Exception:
                pass
        st.json(payload_data if payload_data else {"message": "No additional details payload for this event."})
    else:
        st.info("No records to inspect.")

with tab_chargeback:
    st.subheader("Cluster Hourly Chargeback Breakdown")
    
    cb_raw_df = fetch_cluster_chargebacks(api_key, api_version)
    
    if not cb_raw_df.empty:
        unique_clusters = sorted(cb_raw_df["tenant_cluster_name"].dropna().unique().tolist())
        cluster_options = ["All Clusters"] + unique_clusters
        
        selected_cluster = st.selectbox(
            "Select Cluster Name Filter",
            options=cluster_options,
            index=0,
            help="Filter chargeback charts and tables by a specific cluster or view all."
        )
        
        if selected_cluster != "All Clusters":
            cb_df = cb_raw_df[cb_raw_df["tenant_cluster_name"] == selected_cluster].copy()
        else:
            cb_df = cb_raw_df.copy()

        # Summary KPIs
        total_clusters = len(cb_df)
        total_hourly_cost = cb_df["total_hourly_chargeback_usd"].sum()
        total_vcpus = cb_df["allocated_vcpus"].sum()
        total_storage = cb_df["allocated_storage_gib"].sum()

        mcol1, mcol2, mcol3, mcol4 = st.columns(4)
        mcol1.metric("Selected Clusters", total_clusters)
        mcol2.metric("Total Hourly Cost", f"${total_hourly_cost:.4f}")
        mcol3.metric("Total Allocated vCPUs", f"{total_vcpus:,}")
        mcol4.metric("Total Storage (GiB)", f"{total_storage:,}")

        st.markdown("---")

        if not cb_df.empty:
            # ---------------------------------------------------------
            # Top 10 Executive Analysis Visualizations
            # ---------------------------------------------------------
            st.markdown("### Executive Overview: Top 10 Most Expensive Clusters")
            st.caption("Clear breakdown of hourly costs alongside underlying compute & storage resource allocations.")

            # Isolate top 10 clusters by total hourly chargeback
            top_10_df = cb_df.sort_values(by="total_hourly_chargeback_usd", ascending=False).head(10)

            c_chart1, c_chart2 = st.columns(2)

            with c_chart1:
                # Stacked horizontal bar chart for clear cost breakdown
                cost_melted = top_10_df.melt(
                    id_vars=["tenant_cluster_name"],
                    value_vars=["hourly_compute_cost_usd", "hourly_storage_cost_usd"],
                    var_name="Cost Component",
                    value_name="Hourly Cost ($)"
                )
                cost_melted["Cost Component"] = cost_melted["Cost Component"].map({
                    "hourly_compute_cost_usd": "Compute Cost ($)",
                    "hourly_storage_cost_usd": "Storage Cost ($)"
                })

                fig_top_cost = px.bar(
                    cost_melted,
                    x="Hourly Cost ($)",
                    y="tenant_cluster_name",
                    color="Cost Component",
                    orientation="h",
                    labels={"tenant_cluster_name": "Cluster", "Hourly Cost ($)": "Hourly Cost ($ USD)"},
                    title="Top 10 Clusters by Hourly Cost ($ USD)",
                    template="plotly_white",
                    height=380,
                )
                fig_top_cost.update_layout(
                    yaxis=dict(autorange="reversed"),
                    margin=dict(l=20, r=20, t=40, b=20),
                    legend=dict(orientation="h", y=-0.25, title_text="")
                )
                st.plotly_chart(fig_top_cost, width="stretch")

            with c_chart2:
                # Side-by-side bar chart showing vCPUs and Storage allocations
                res_melted = top_10_df.melt(
                    id_vars=["tenant_cluster_name"],
                    value_vars=["allocated_vcpus", "allocated_storage_gib"],
                    var_name="Resource Metric",
                    value_name="Allocation"
                )
                res_melted["Resource Metric"] = res_melted["Resource Metric"].map({
                    "allocated_vcpus": "vCPUs",
                    "allocated_storage_gib": "Storage (GiB)"
                })

                fig_top_res = px.bar(
                    res_melted,
                    x="Allocation",
                    y="tenant_cluster_name",
                    color="Resource Metric",
                    barmode="group",
                    orientation="h",
                    labels={"tenant_cluster_name": "Cluster", "Allocation": "Allocated Units"},
                    title="Resource Allocations (vCPUs vs Storage GiB)",
                    template="plotly_white",
                    height=380,
                )
                fig_top_res.update_layout(
                    yaxis=dict(autorange="reversed"),
                    margin=dict(l=20, r=20, t=40, b=20),
                    legend=dict(orientation="h", y=-0.25, title_text="")
                )
                st.plotly_chart(fig_top_res, width="stretch")

            st.markdown("---")
            st.markdown("### Active Clusters Detail Table")
            st.dataframe(
                cb_df,
                width="stretch",
                hide_index=True,
                column_config={
                    "tenant_cluster_name": "Cluster Name",
                    "cluster_id": "Cluster ID",
                    "workspace_id": "Workspace ID",
                    "environment": "Environment",
                    "cost_center": "Cost Center",
                    "allocated_vcpus": "vCPUs",
                    "allocated_storage_gib": "Storage (GiB)",
                    "hourly_compute_cost_usd": st.column_config.NumberColumn("Compute ($/hr)", format="$%.4f"),
                    "hourly_storage_cost_usd": st.column_config.NumberColumn("Storage ($/hr)", format="$%.4f"),
                    "total_hourly_chargeback_usd": st.column_config.NumberColumn("Total Chargeback ($/hr)", format="$%.4f"),
                }
            )
        else:
            st.info(f"No clusters found for cluster name: `{selected_cluster}`.")
    else:
        st.info("No active clusters in state `CREATED` were found.")
