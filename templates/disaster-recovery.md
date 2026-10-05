# Service Outage Recovery Plan

**Incident ID:** [IR-YYYYMMDD-##]  
**Service / business owner:** [service, person]  
**Primary host(s):** [hostname, IP, OS, role]  
**Start time / timezone:** [YYYY-MM-DD HH:MM TZ]  
**Incident lead / scribe:** [names]  
**Current state:** [Investigating / Containing / Recovering / Validating / Restored]

## Service Impact

- **Scored service and protocol/port:** [name, TCP/UDP, port]
- **Last known good / first failed check:** [time and evidence]
- **Scoring-network probe:** [source, command/test, result]
- **Business inject / SLA deadline:** [ID, deadline, impact]
- **Known dependencies:** [DNS, AD, database, filesystem, upstream API, mail]

## Immediate Stabilization

| Time | Action | Owner | Result | Rollback / next step |
| --- | --- | --- | --- | --- |
| [time] | [preserve evidence; avoid blind restart] | [name] | [result] | [step] |

1. Confirm outage from a second vantage and preserve relevant logs/configuration before changes.
2. Identify recent changes, resource exhaustion, dependency failure, and active compromise indicators.
3. Notify the incident lead and the authorized White/Orange Team contact if scoring, access, or inject timing may be affected.
4. Do not disable firewall rules or isolate the host without preserving the scoring/admin path and documenting approval.

## Recovery Decision

- **Chosen recovery path:** [restart / rollback config / patch / restore backup / failover]
- **Why it is least risky:** [evidence and service dependencies]
- **Authorized by:** [name, role, time]
- **Data recovery point / backup:** [location, timestamp, verification]
- **Expected impact:** [brief user/service effects]

## Execution Checklist

- [ ] Confirmed system/edition/domain/init and service version.
- [ ] Captured current state, logs, hashes, config, and listener sockets.
- [ ] Confirmed backup/rollback is readable and appropriate.
- [ ] Applied one change at a time; recorded exact command and output.
- [ ] Validated configuration before reload/restart.
- [ ] Confirmed dependent services, authentication, and data integrity.
- [ ] Verified service from scoring network and team admin path.
- [ ] Monitored for recurrence for [duration].
- [ ] Sent status update and completed incident report.

## Service Verification

| Check | Source / command | Expected | Actual | Time / result |
| --- | --- | --- | --- | --- |
| Listener | [host-side socket check] | [IP:port] | [result] | [time] |
| Protocol | [curl / DNS query / SMTP test / DB check] | [response] | [result] | [time] |
| Scoring path | [approved scoring-vantage probe] | [green/check] | [result] | [time] |
| Business function | [real application transaction] | [expected result] | [result] | [time] |

## Handoff

**Current status:** [restored / degraded / still down]  
**Outstanding risks:** [items]  
**Next owner and action:** [name, action, deadline]  
**White/Orange Team contact and acknowledgement:** [reference/time]  
**Scribe / handoff time:** [name/time]
