# CockroachDB Cloud Organization Audit Logs

**Audience:** VP of Infrastructure, SecOps Lead, Lead Enterprise Architect, Head of Compliance.

**Objective:** Prove enterprise-readiness, governance, and auditability on CockroachDB Cloud, demonstrate real-time incident forensics down to the minute, and show how easily it streams into corporate SIEMs (Datadog/Grafana).

## Launch the demo

To launch the demo start the Streamlit application

```bash
streamlit run cockroach_audit.py
```

Expected output:

```
2026-10-01 14:16:30.517 Uvicorn server started on :::8501

  You can now view your Streamlit app in your browser.

  Local URL: http://localhost:8501
  Network URL: http://\<your local IP\>:8501

  Help agents write better Streamlit apps?
  Install the official Streamlit skills by running streamlit skills in your terminal.
```

## The Hook (Setting the Stage)

*"When enterprises run mission-critical databases in the cloud, CISOs and SecOps teams always have the same non-negotiable requirement:

'We need an immutable audit trail of who touched our infrastructure, what they changed, and when.'
CockroachDB Cloud records every administrative and control-plane action via our Organization Audit Log API. To show you what this telemetry looks like in practice, we built this explorer dashboard connected live to our Cloud API. Everything you see here is available programmatically to your security teams."*

## Ingestion Coverage & Executive KPIs (Immediate Situational Awareness)

(Point to the top Ingestion Coverage card and the 4 KPI cards)

*"Right at the top, the dashboard gives immediate situational awareness:

Ingested Window & Velocity: Look at this coverage card. It shows the exact 24-hour UTC window we pulled (From and To). 

In an active enterprise account with CI/CD and Terraform, hundreds of events can fire in just a few hours. This card confirms whether our search window has 100% data coverage or if we hit an API ceiling.
Automation Ratio (API vs. UI): If your policy is Infrastructure-as-Code via Terraform, you want this percentage high (90%+). If you see unexpected spikes in Console clicks (UI), that immediately tells SecOps that someone is making manual, out-of-band changes in production.
High-Impact Governance Banner: Notice this red expandable alert. Out of hundreds of background events, our rules instantly isolate critical actions: someone granting Org Admin, deleting a cluster, or modifying firewall allowlists. The table provides full vertical scrolling, so you never miss a high-risk event."*

## Surgical Incident Investigation (The New Date & Time Precision Feature)

(Move your cursor to the sidebar, open the Investigation Scope dropdown, and select Custom Incident Window)
SE:
*"Now, imagine a real-world scenario: your SOC receives an alert that an unauthorized firewall rule was active last Thursday between 2:00 PM and 4:00 PM UTC.
In many systems, you’d have to download gigabytes of raw logs or file a support ticket. Here, we can zero in with surgical precision:
We select Custom Incident Window.
We specify the exact date down to the minute: 2026-09-26 14:00 to 2026-09-26 16:00 UTC.
Watch what happens: instead of fetching thousands of unneeded records from today, our app instructs the CockroachDB Cloud API to start paginating directly from that target timestamp. In seconds, we've isolated the incident without overwhelming your browser or burning through rate limits.
And when an analyst finishes their investigation? One click on '↺ Reset All' instantly clears all filters, time ranges, and caches back to a clean real-time view."*

## Tab-by-Tab Walkthrough
Tab 1: 📋 Event Log Table (Compliance & Audit Evidence)
(Click on the Event Log Table tab)
SE:
*"This tab is your compliance officer’s dream during a SOC 2, ISO 27001, or HIPAA audit.
Why it matters: When auditors ask: 'Prove to me that only approved personnel made changes to production clusters during Q3,' you don't need a custom script.
The Capabilities: Filter by Category (e.g., Access & RBAC), Cluster, or Actor. With one click on 'Download Filtered Audit Logs as CSV', you hand the auditor the exact evidence package they need in seconds."*

Tab 2: 👤 Actor Breakdown (Insider Threat & Rogue Key Detection)
(Click on the Actor Breakdown tab)
SE:
*"Here we visualize the most active actors in the organization, categorized by whether they acted as a human user or an automated Service Account.
Why it matters: This surfaces behavioral anomalies at a glance:
Did an offshore contractor's personal email suddenly trigger 50 changes on a Sunday morning?
Is an old Terraform service account still issuing API calls after being decommissioned?
You can spot privilege drift and zombie service accounts instantly."*

Tab 3: 🔍 Deep-Dive Payload Inspector (Forensics & Root Cause)
(Click on the Payload Inspector tab, select an event, and highlight the raw JSON)
SE:
*"When an incident occurs, summaries aren't enough—you need verifiable forensics.
Why it matters: Look at the JSON payload here. When an allowlist changes, it doesn’t just say ADD_IP_ALLOWLIST; it logs the exact CIDR block added, the source IP of the client that executed the command, and the session ID.
If a cluster was modified, it details whether CPU was scaled, whether the maintenance window was moved, or if a database user had their password reset. You have complete non-repudiation."*

## The Transition: "How Do We Ingest This Into Datadog or Grafana?"
Customer Question: "This UI is great for ad-hoc queries, but our SecOps team works in Datadog and Grafana. Can we pipe this into our existing SIEM?"
SE:
*"100%. In fact, that is the exact enterprise design pattern this API was built for.
First, let's clarify an important architectural distinction:
CockroachDB Engine Logs (SQL queries, slow queries, cluster health) can be streamed natively from the cluster to Amazon CloudWatch, GCP Cloud Logging, or Azure Monitor using our built-in log export.
Cloud Control-Plane Audit Logs (the org-level administrative actions shown here) are polled via the /v1/auditlogevents REST API.
Here is how simple it is to pipeline these events into your SIEM:"*

Option A: Ingesting into Datadog (The Serverless Poller Pattern)

```
[CockroachDB Cloud API] 
       │ (GET /v1/auditlogevents?starting_from=...)
       ▼
[AWS Lambda / Cloud Function / Cron Worker]
       │ (Persists last 'next_starting_from' in SSM / Redis)
       ▼
[Datadog Logs Intake HTTP API] (POST https://http-intake.logs.datadoghq.com)
```

SE Walkthrough:
The Poller: Deploy a lightweight AWS Lambda or scheduled container running every 5 minutes.
State Management via next_starting_from:
The function calls GET /v1/auditlogevents?sort_order=ASC&starting_from={last_checkpoint}.
The response returns a batch of events and a next_starting_from cursor timestamp.
Store that timestamp in AWS SSM Parameter Store or Secrets Manager as your watermark.
Forwarding to Datadog:
The Lambda posts the batch directly to Datadog's Logs HTTP API with tags like service:cockroach-cloud-audit, env:prod.
In Datadog, set up a Cloud SIEM Detection Rule: e.g., trigger a P1 alert if @action:AUDIT_LOG_ACTION_ADD_IP_ALLOWLIST allows 0.0.0.0/0."*

Option B: Ingesting into Grafana (Loki)

```
[CockroachDB Cloud API] 
       │
       ▼
[Vector / FluentBit / Python Ingestor]
       │ (Parses JSON & tags labels)
       ▼
[Grafana Loki] (POST /loki/api/v1/push) ──► [Grafana Dashboards & Alerting]
```

SE Walkthrough:
Agent Pipeline: Use an observability collector like Vector or a lightweight Python poller to ingest the /v1/auditlogevents stream.
Push to Loki: Stream the entries to Loki’s /loki/api/v1/push endpoint, tagging labels like {source="cockroach_cloud", org_id="acme_corp"}.
Grafana Alerting: In Grafana, write simple LogQL alerts:
{source="cockroach_cloud"} | json | action = "AUDIT_LOG_ACTION_DELETE_CLUSTER"
Route that alert immediately to PagerDuty or your SecOps Slack channel."*

6. Summary & Close
SE:
*"To wrap up: with CockroachDB Cloud, you don't have to compromise on governance. You get:
Immediate ad-hoc forensics via this dashboard when an incident needs answers fast.
One-click evidence generation for your compliance audits.
A clean REST API that integrates seamlessly into your existing Datadog or Grafana monitoring stack without forcing your security team to learn a new tool."*



