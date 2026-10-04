#!/usr/bin/env python3
"""Render first-hour Splunk configs and bounded SPL from config/splunk.json."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "splunk.json"
OUTPUT = ROOT / "generated" / "splunk"
INDEX_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,99}$")


def main() -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    host = str(config["indexer_host"]).strip()
    port = int(config["indexer_port"])
    indexes = config["indexes"]
    window = str(config["time_window"])
    if not host or any(ch.isspace() for ch in host) or "REPLACE_" in host:
        raise SystemExit("Set a real indexer host in config/splunk.json")
    if not 1 <= port <= 65535:
        raise SystemExit("indexer_port must be in 1..65535")
    if not re.fullmatch(r"-[1-9][0-9]*(?:[smhd])", window):
        raise SystemExit("time_window must be a negative duration such as -15m or -1h")
    required = {"windows_auth", "linux_auth", "sysmon", "web_access", "network_egress"}
    if set(indexes) != required:
        raise SystemExit(f"indexes must contain exactly {sorted(required)}")
    for name in indexes.values():
        if not INDEX_PATTERN.fullmatch(str(name)):
            raise SystemExit(f"Invalid Splunk index name: {name!r}")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    outputs = f"""[tcpout]\ndefaultGroup = ccdc_indexers\n\n[tcpout:ccdc_indexers]\nserver = {host}:{port}\nuseACK = true\n"""
    windows = f"""[WinEventLog://Security]\nenabled = 1\nrenderXml = true\nindex = {indexes['windows_auth']}\nsourcetype = XmlWinEventLog:Security\n\n[WinEventLog://Microsoft-Windows-Sysmon/Operational]\nenabled = 1\nrenderXml = true\nindex = {indexes['sysmon']}\nsourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\n\n[WinEventLog://Microsoft-Windows-DeviceSetupManager/Admin]\nenabled = 1\nrenderXml = true\nindex = {indexes['windows_auth']}\nsourcetype = XmlWinEventLog:Microsoft-Windows-DeviceSetupManager/Admin\n\n[WinEventLog://Microsoft-Windows-DriverFrameworks-UserMode/Operational]\nenabled = 1\nrenderXml = true\nindex = {indexes['windows_auth']}\nsourcetype = XmlWinEventLog:Microsoft-Windows-DriverFrameworks-UserMode/Operational\n"""
    linux = f"""[monitor:///var/log/auth.log]\ndisabled = 0\nindex = {indexes['linux_auth']}\nsourcetype = linux_secure\n\n[monitor:///var/log/secure]\ndisabled = 0\nindex = {indexes['linux_auth']}\nsourcetype = linux_secure\n\n[monitor:///var/log/apache2/access.log]\ndisabled = 0\nindex = {indexes['web_access']}\nsourcetype = access_combined\n\n[monitor:///var/log/nginx/access.log]\ndisabled = 0\nindex = {indexes['web_access']}\nsourcetype = access_combined\n\n[monitor:///var/log/httpd/access_log]\ndisabled = 0\nindex = {indexes['web_access']}\nsourcetype = access_combined\n"""
    indexer_indexes = "\n".join(
        f"[{name}]\nhomePath = $SPLUNK_DB/{name}/db\ncoldPath = $SPLUNK_DB/{name}/colddb\nthawedPath = $SPLUNK_DB/{name}/thaweddb"
        for name in sorted(set(indexes.values()))
    ) + "\n"
    searches = f"""# Windows authentication successes/failures
index={indexes['windows_auth']} sourcetype=XmlWinEventLog:Security (EventCode=4624 OR EventCode=4625) earliest={window} latest=now | stats count by EventCode TargetUserName host

index={indexes['sysmon']} sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 earliest={window} latest=now (Image="*w3wp.exe" OR Image="*php-cgi.exe" OR Image="*bash.exe" OR Image="*sh.exe" OR Image="*powershell.exe" OR Image="*wmic.exe" OR Image="*psexec*" OR Image="*ssh.exe") | stats count values(ParentImage) as parents values(CommandLine) as commands by User Image host

index={indexes['linux_auth']} sourcetype=linux_secure earliest={window} latest=now ("Failed password" OR "Invalid user" OR "authentication failure") | stats count by host source user

index={indexes['web_access']} sourcetype=access_combined earliest={window} latest=now status>=400 | stats count by host status uri_path

index={indexes['network_egress']} sourcetype=netflow earliest=-7d latest=now action=allowed bytes_out=* | bin _time span=5m | stats sum(bytes_out) as bytes_out by host _time | sort 0 host _time | streamstats window=2016 current=f avg(bytes_out) as baseline stdev(bytes_out) as baseline_sd by host | where _time>=relative_time(now(),"-15m") AND bytes_out>baseline+(3*baseline_sd) AND bytes_out>104857600 | stats max(bytes_out) as bytes_out max(baseline) as baseline max(baseline_sd) as baseline_sd by host _time

index={indexes['windows_auth']} (sourcetype=XmlWinEventLog:Microsoft-Windows-DeviceSetupManager/Admin OR sourcetype=XmlWinEventLog:Microsoft-Windows-DriverFrameworks-UserMode/Operational) (EventCode=20001 OR EventCode=2003) earliest={window} latest=now | stats count values(Message) as details by host sourcetype EventCode _time
"""
    query_blocks = searches.strip().split("\n\n")
    markdown = "# First-Hour SPL Searches\n\nEach query is independent. Index, sourcetype, and time bounds precede the first pipe.\n\n"
    headings = (
        "Windows authentication",
        "Sysmon process creation",
        "Linux authentication failures",
        "Web server errors",
        "Outbound volume anomaly (requires normalized firewall/netflow fields)",
        "USB device setup events (requires Windows device event channels)",
    )
    for heading, query in zip(headings, query_blocks):
        markdown += f"## {heading}\n\n```spl\n{query}\n```\n\n"
        if heading.startswith("Outbound volume"):
            markdown += "Requires firewall or flow telemetry in the configured `network_egress` index with `sourcetype=netflow` and normalized `host`, `bytes_out`, and `action=allowed` fields; normalize field extractions before enabling. It compares 5-minute host totals to that host's preceding 7-day rolling baseline and applies a 100 MiB floor plus 3 standard deviations.\n\n"
        elif heading.startswith("USB device"):
            markdown += "Requires `Microsoft-Windows-DeviceSetupManager/Admin` or `Microsoft-Windows-DriverFrameworks-UserMode/Operational` forwarded into the Windows auth index. The generator enables both channels in `windows-inputs.conf`; verify channel availability and event IDs on the target before relying on this search.\n\n"
    markdown = markdown.rstrip() + "\n"
    (OUTPUT / "outputs.conf").write_text(outputs, encoding="utf-8")
    (OUTPUT / "windows-inputs.conf").write_text(windows, encoding="utf-8")
    (OUTPUT / "linux-inputs.conf").write_text(linux, encoding="utf-8")
    (OUTPUT / "indexes.conf").write_text(indexer_indexes, encoding="utf-8")
    (OUTPUT / "first-hour-searches.md").write_text(markdown, encoding="utf-8")
    print(f"Rendered Splunk configs and searches under {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
