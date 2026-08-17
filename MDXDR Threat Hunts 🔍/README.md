# 🔎 MDXDR Threat Hunts

Threat hunting queries for Microsoft Defender XDR, split into two categories by **what causes them to exist**.

---

## ⚖️ The difference at a glance

| | 📅 Daily Hunts | 🎯 TI-Based Hunts |
| --- | --- | --- |
| **Triggered by** | A schedule | Published threat intel |
| **Looks for** | Attacker *behavior* | Specific *indicators* |
| **Precision** | Moderate — needs triage | High — a match is a match |
| **Recall** | High — catches unknown threats | Low — only what's in the report |
| **Lifespan** | Permanent | Decays as infrastructure rotates |
| **Lookback** | Short, rolling (7–14 days) | Long retro-hunt first (30–120 days) |

---

## 📅 Daily Hunts

**Behavioral detection, run on a recurring cadence.**

These hunt for *how attackers operate* rather than *who they are*. They don't care whether a campaign has been named or an IOC published — they look for the techniques that appear in nearly every intrusion regardless of actor.

Examples: suspicious PowerShell execution, EDR evasion, LSASS credential dumping, log clearing, ransomware preparation, lateral movement, web shells, unauthorized remote tools, MFA fatigue, data exfiltration.

**Why they matter:** they're the only thing that catches a threat nobody has written about yet. A brand-new implant still has to dump credentials, establish persistence, and move laterally — and those behaviors look the same whether the malware is a decade old or shipped this morning.

**What they cost:** false positives. Behavioral logic can't distinguish an administrator's legitimate `PsExec` run from an attacker's without environmental context, so these need ongoing tuning — exclusion lists, known-benign parent fingerprints, threshold adjustments. That tuning *is* the work, and it's what makes them yours rather than generic.

> 💡 A daily hunt is never "finished." Each false positive you fingerprint makes the next run cleaner.

---

## 🎯 Threat Intelligence Based Hunts

**Indicator matching, built in response to a specific report — but only when the report matches your environment.**

These exist because something was published — a vendor advisory, an FBI FLASH, a CISA alert, a supply-chain disclosure. They match concrete artifacts: file hashes, C2 domains and IPs, package versions, registry paths, hardcoded strings.

Examples: named malware families, supply-chain compromises, APT campaign IOC sets, threat-feed correlation.

### 🧪 Relevance filter — build one only when it applies

Not every published campaign warrants a hunt. Before writing one, check whether the threat actor or CVE is actually relevant to your infrastructure. If neither of the following is true, skip it and move on:

- **Does the threat actor target your industry, geography, or company profile?** A ransomware crew focused on healthcare doesn't need a bespoke hunt in a logistics environment. An APT targeting defense contractors isn't your priority in retail.
- **Does the CVE affect software, hardware, or a cloud service you actually run?** A critical FortiGate CVE is only critical to you if you have FortiGates. A Log4j-class vulnerability is only relevant where the affected component is deployed.

The relevance filter is the whole point. TI hunts have real cost — engineering time to build, storage cost on retro-hunts, and analyst attention when they fire. Spending that on a campaign you're not exposed to is wasted effort that could go into hunts that actually protect you.

**Why they matter (when they apply):** near-zero false positives. A hardcoded C2 domain or a unique campaign token has no legitimate reason to appear in your environment. When one of these fires, you skip triage and go straight to response.

**What they cost:** they only find what the report described. An actor who rotates infrastructure — which is most of them — walks past a pure IOC hunt. And the hunt goes stale the moment the campaign moves on.

> 💡 Run relevant hunts at a **long lookback first** (30–120 days depending on the campaign window), then drop to a short cadence for ongoing monitoring. The retro-hunt is where most of the value is — you're asking whether you were already hit before the intel existed.

---

## 🧭 Which folder does a new hunt go in?

First: **is it worth building at all?** If it's TI-based and doesn't clear the relevance filter above, it doesn't get built.

If it does, ask: **would this query still make sense if the report it came from didn't exist?**

- **Yes** → Daily Hunts. It describes a technique.
- **No** → TI-Based. It describes a campaign.

A hunt for "PowerShell downloading and executing a remote payload" belongs in Daily — that's a technique that predates any specific actor and will outlive all of them. A hunt for a specific C2 domain and package version belongs in TI-Based, and will be irrelevant within months.

---

## 🔀 On overlap

**Feed enrichment doesn't make a hunt TI-based.** Several daily hunts correlate against threat-intel feeds to boost severity — malicious-IP scoring on sign-ins, hash matching on email attachments. Those are still behavioral hunts; the feed is a *modifier*, not the reason the query exists. If you removed the feed, the hunt would still function.

The test is whether the hunt would be deleted once the campaign ends. Behavioral hunts with TI enrichment stay. Campaign hunts go.

---

## 🔄 Lifecycle

**Daily Hunts** get tuned, never retired. When one turns noisy, fingerprint the benign pattern and move on.

**TI-Based Hunts** should be reviewed periodically. Once a campaign's infrastructure is fully burned and the retro-hunt came back clean, the query is dead weight — archive it. But first, check whether any *behavioral* element in it is worth promoting: the durable half of a campaign hunt (a persistence mechanism, a masquerade pattern, a staging path) often deserves a permanent home in Daily Hunts even after the IOCs rot.

> That promotion step is where a TI hunt pays off twice — once for the campaign, once for everything that reuses the technique.

---

## 📌 Notes

Both folders assume the same conventions: MITRE ATT&CK mappings in each query header, a consistent lookback variable at the top, and environment-specific exclusion lists kept as placeholders rather than hardcoded.

Run both. Neither replaces the other — TI-based hunts are precise but blind to what hasn't been reported, and daily hunts are broad but need a human to read them.