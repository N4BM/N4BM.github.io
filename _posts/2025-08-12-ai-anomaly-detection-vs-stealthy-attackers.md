---
title: "When AI Anomaly Detection Meets Stealthy Attackers"
date: 2025-08-12 13:00:00 +0000
author: n4bm
categories:
  - Detection
  - AI Security
tags:
  - anomaly-detection
  - ai-security
  - blue-team
  - detection-engineering
image:
  path: /assets/img/AI-anomaly-detection-cover.png
  alt: "Anomaly Detection"
---

# When AI Anomaly Detection Meets Stealthy Attackers

**TL;DR:** Anomaly detection is excellent at catching what looks *weird*. Sophisticated attackers study your baseline and learn to look *boring*. The fix isn’t to ditch AI—it’s to combine it with identity-aware rules, deception, and continuous red-teaming of the models themselves.

---

## The promise: AI sees what humans miss

Anomaly detection models learn what “normal” looks like in your environment and surface the outliers. You don’t need perfect signatures; you need patterns. In practice, these systems (Isolation Forests, one-class SVMs, clustering, autoencoders) shine at things like:

- **Impossible travel**: same user “logging in” from Riyadh and Paris 30 minutes apart.
- **Weird timing**: a service account pulling gigabytes at 3:12 a.m. on a Sunday.
- **Beaconing patterns**: periodic egress to a domain no one has ever contacted.
- **New rare combinations**: a finance user suddenly running PowerShell with network recon commands.

The upside: AI spots subtle shifts faster than humans and scales across massive telemetry.

---

## The catch: smart attackers play normal

If an attacker understands your detection stack, they won’t spike your charts—they’ll **blend into your baseline**. Common evasion patterns:

- **Slow-and-low**: exfiltrate 5–10 MB per hour over weeks instead of a 20 GB dump in one night.
- **Living off the land**: use PowerShell, WMI, certutil, or existing admin tools to avoid “malware” signatures.
- **Shadowing real users**: hijack a routine (e.g., nightly backup) and piggyback your traffic timing and volume.
- **Baseline poisoning**: dwell long enough that the model quietly learns your malicious activity as “normal.”
- **Shape-shifting identity**: rotate through low-privilege accounts, each doing just a little bit—never enough to trip a single-entity threshold.

Bottom line: anomaly detection raises the bar, but patient attackers will try to step over it.

---

## Why pure anomaly detection isn’t enough

1. **Alert sensitivity is a tradeoff.** If you turn the dial to “catch everything,” analysts drown. Turn it down, and subtle attacks slip by.
2. **Concept drift is real.** Business behavior changes (new apps, quarter-end crunch), and the model’s notion of “normal” moves with it.
3. **Context matters.** “5 GB to S3” is benign for a data team and terrifying for HR. Raw anomalies miss identity and intent.
4. **Adversaries adapt.** Once they see what trips an alert, they iterate—just like you do.

---

## Think like an attacker: how to look normal (so you can detect it)

If I were trying to evade your detectors, I would:
- **Match rhythms**: send data only during office hours and within typical bandwidth for the role.
- **Mimic paths**: use the same SaaS and egress routes the victim uses every day.
- **Borrow tools**: schedule tasks, use signed binaries, and reuse scripts already on the host.
- **Spread actions**: split steps across machines and accounts so no single entity looks odd.
- **Age into the baseline**: maintain low activity for weeks so retraining absorbs me.

Now, turn each move into a **countermeasure**.

---

## Make “normal” hard to fake: a defender’s playbook

**1) Tie behavior to identity and privilege**  
- Maintain **per-entity baselines** (user, service account, device). A junior intern and a DBA don’t share a baseline.
- Add **role + sensitivity** to features: data classifications, system criticality, and the business calendar.

**2) Detect slow-and-low with accumulation, not spikes**  
- Use rolling **cumulative sums** and **EWMA (exponentially weighted moving averages)** to flag long, gentle climbs.
- Alert on **destination diversity** growth (number of distinct external endpoints per user/week).

**3) Blend AI with crisp rules**  
- Create **guardrails** that don’t care about averages: “This account must never access production payroll,” “No interactive PowerShell for service accounts,” “No outbound traffic to first-seen domains from Tier-0 assets.”
- Use AI to triage and rank, use rules to **hard-stop** known-bad patterns.

**4) Add deception to the baseline**  
- **Honey credentials**, **canary files**, and **decoy SaaS apps** are cheap tripwires. Normal users never touch them; attackers eventually do.
- Plant **canary egress domains** and watch for resolution attempts.

**5) Defend the model itself**  
- **Freeze a reference baseline** and compare against the live model to catch drift or poisoning.
- Keep a **clean validation set** from a prior period—don’t let the attacker “train” your model.
- Run **purple-team simulations**: emulate slow exfil, ticket spraying, and benign tool abuse; measure true/false positives.

**6) Close the feedback loop**  
- Every investigated alert should update **labels and features**. Promote high-signal features; demote noisy ones.
- Treat detections like **products**: version them, test them, measure precision/recall, and retire what doesn’t work.

---

## Quick wins you can deploy

- **Per-user upload budget**: baseline daily egress per user; alert at 3× EWMA over a 7–14 day window.
- **First-seen destination & process combo**: if a user/process talks to a domain never seen in org history, bump the risk score—especially from Tier-0 hosts.
- **Service account constraints**: no interactive logins, no token theft-prone privileges, and strict allowed paths.
- **Rendezvous beacons**: alert on near-periodic (e.g., every 60±5 seconds) outbound patterns to rare domains.
- **Canary everything**: a fake “Payroll_2025_Q3.xlsx” with a beacon on open/download; a few fake OIDC apps in your IdP.

---

## A mini case study

A finance workstation began uploading small encrypted blobs to a clean-looking cloud endpoint—**only during lunch hours**, ~8 MB each time, ~1.5 GB total over three weeks. No spikes. AV clean. EDR quiet.

What caught it?  
- A **destination diversity** rule noted that this user had never contacted that ASN before.  
- An **EWMA-based egress budget** flagged a 3.4× rise across 14 days.  
- A **canary file** was touched from the same host two days earlier.

The triage pipeline promoted the alert to high. Memory scan found a side-loaded DLL abusing the user’s browser session. Slow-and-low, but not invisible.

---

## The takeaway

Anomaly detection isn’t a silver bullet, but it’s not hype either. It **raises the floor** of what you can see. To raise the **ceiling** of what you can catch, pair AI with identity-aware rules, deception, and an explicit defense of the models themselves.

In short: **Teach your AI to see normal—and teach your program to doubt it.**


## Detection recipes (Splunk & Elastic)

> The goal here is to make “normal” hard to fake. Below are practical queries you can adapt. Names of indexes/sourcetypes will vary in your environment.

### 1) Per-user upload budget (rolling baseline)

**Splunk (SPL)** – 14‑day rolling average with 3× threshold:
```spl
index=proxy OR index=fw
| bin _time span=1d
| stats sum(bytes_out) as bytes by user _time
| sort 0 user _time
| streamstats window=14 avg(bytes) as avg14 stdev(bytes) as sd14 by user
| eval ratio=bytes/avg14
| where avg14>0 AND ratio>=3
| eval msg=printf("Egress rise: user=%s bytes=%d avg14=%.0f ratio=%.2f", user, bytes, avg14, ratio)
```

**Elastic (Lens/TSVB approach)** – Create a time series of `sum(bytes_out)` grouped by `user.keyword`, add a 14‑day moving average, then create a ratio (`bytes / moving_average`) and alert when `ratio >= 3`.  
*(If using raw ES DSL, use a `moving_fn` pipeline agg over a date_histogram per user.)*

---

### 2) First‑seen destination & process combo

**Splunk (SPL)** – naive “first seen in 30 days” approach, then alert on today’s firsts:
```spl
index=edr OR index=sysmon (EventCode=3 OR EventID=3) dest_domain=* process_name=*
| eval combo=process_name."→".dest_domain
| bin _time span=1d
| stats earliest(_time) as first_seen by combo
| where first_seen >= relative_time(now(), "-1d@d")
```

**Production tip:** Maintain a summary index/lookup (`known_combos.csv`). Anything not in it is “new”.

**Elastic (KQL + Rule)**  
KQL filter for candidate events:
```
event.category:network and process.name:* and destination.domain:*
```
Use a rule with a *Cardinality* condition (unique `process.name + destination.domain`) scoped over a long lookback (e.g., 30–90 days) to approximate “first seen.”

---

### 3) Service accounts: block interactive logons

**Splunk (SPL)** – Windows 4624 LogonType=2 from service accounts:
```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 LogonType=2
| lookup service_accounts.csv account as TargetUserName OUTPUT is_service_account
| search is_service_account=true
| stats count by TargetUserName, WorkstationName, IpAddress
```

**Elastic (KQL)** – with a maintained tag/lookup:
```
event.code: "4624" and winlog.event_data.LogonType: "2" and user.name: ("svc_*", "sa_*") 
```
*(Prefer a proper directory/IdP attribute to tag service accounts rather than name patterns.)*

---

### 4) Rendezvous beacons (near‑periodic outbound)

**Splunk (SPL)** – detect low jitter between consecutive calls:
```spl
index=proxy dest_category!=internal dest_domain=*
| sort 0 src_ip dest_domain _time
| streamstats window=1 current=f last(_time) as prev by src_ip dest_domain
| eval delta=_time - prev
| eventstats avg(delta) as avg_delta stdev(delta) as sd_delta count as n by src_ip dest_domain
| where n>=8 AND avg_delta>=30 AND sd_delta<=5
| table _time src_ip dest_domain avg_delta sd_delta n
```

**Elastic (EQL)** – approximate with sequence gap checks or use a Transform to compute inter‑arrival deltas, then alert on `low stddev` and `n >= 8`.

---

### 5) Canary everything (files, creds, domains)

**Splunk (SPL)** – canary file access on tier‑0 hosts:
```spl
index=edr OR index=sysmon (EventID=11 OR EventCode=4663)
FileName="*Payroll_2025_Q3.xlsx"
| search host IN ([ | inputlookup tier0_hosts.csv | fields host ])
| stats earliest(_time) as first_touch, values(user) as users, values(process_name) as procs by host FileName
```

**Elastic (KQL)** – canary credential usage in authentication logs:
```
event.category:authentication and user.name: "canary_svc@corp.local" and event.outcome: "success"
```

---

### Model hygiene (anti‑poisoning)

- Freeze a **reference baseline** and compare model outputs weekly.
- Keep a **clean validation slice** from a prior period for health checks.
- Log and review **feature drift** (e.g., PSI/JS divergence) for key features.
- Version detection content; measure precision/recall; retire noisy rules.

---

## Public‑friendly checklist

- [ ] Per‑entity baselines (user, device, service account) with role context  
- [ ] Rolling accumulation features (EWMA/MA), not just spikes  
- [ ] Identity + data sensitivity in feature set  
- [ ] Guardrail rules for “never” and “always require MFA/Just‑in‑Time” cases  
- [ ] Deception: canary files/creds/egress domains  
- [ ] Drift/poisoning checks and model versioning  
- [ ] Purple‑team simulations for slow‑and‑low, LOTL, beaconing  
- [ ] Feedback loop: promote high‑signal features; demote noisy ones
