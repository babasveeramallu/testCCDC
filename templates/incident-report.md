# Security Incident Report

**Incident ID:** [IR-YYYYMMDD-##]  
**Prepared by / role:** [name, role]  
**Reported to:** [White Team / Orange Team / other authorized contact]  
**Report time and timezone:** [YYYY-MM-DD HH:MM TZ]  
**Status:** [Open / Contained / Monitoring / Closed]

## Executive Summary

[In 2-4 sentences: what happened, which system/service was affected, current business and scoring impact, and present status. Write for a reader who was not present.]

## Timeline

| Time (with timezone) | Event / observation | Source or evidence ID | Action / owner |
| --- | --- | --- | --- |
| [HH:MM] | [Fact, not inference] | [log path, event ID, screenshot ID] | [action, person] |

## Affected Systems and Services

| Host / IP | OS / role | Service / port | Availability before and after | Data or identity impact |
| --- | --- | --- | --- | --- |
| [host] | [role] | [service] | [probe result and times] | [known / unknown] |

## Detection and Evidence

- **Detection source:** [event log, SIEM search, service monitor, user report]
- **Attacker activity observed:** [source address, account, process, file, timestamps; distinguish verified facts from hypotheses]
- **Evidence preserved:** [path, hash, collection time, collector; do not attach secrets]
- **Related Splunk search / alert ID:** [search, index/sourcetype, time range]

## Impact

- **Confidentiality / integrity / availability:** [known effects; state what has not been established]
- **Scoring-service impact:** [service probe, source, port, result, interval]
- **Business inject / SLA impact:** [inject ID, deadline, customer-facing effect]
- **Systems not yet assessed:** [list]

## Response Actions

| Action | Time | Operator | Result / verification | Rollback or follow-up |
| --- | --- | --- | --- | --- |
| [containment / credential disable / firewall rule] | [time] | [name] | [measured result] | [details] |

## Recovery and Validation

1. [Restore or patch from trusted source; record version/hash.]  
2. [Validate configuration, dependencies, and data integrity.]  
3. [Verify service from scoring network and team admin path; record exact probe and result.]  
4. [Monitor for recurrence through time / search.]  
5. [Notify White/Orange Team and record acknowledgement.]

## Open Questions and Next Actions

| Question / task | Owner | Due time | Status |
| --- | --- | --- | --- |
| [item] | [name] | [time] | [open] |

## Approvals / Handoff

**Prepared by:** [name / time]  
**Reviewed by:** [name / time]  
**White Team acknowledgement or incident reference:** [reference]
