#!/usr/bin/env python3
"""Verify this lab's immutable CSV and expected findings using the standard library.

This checks source data. It does not execute KQL or validate an operational detector.
"""
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import base64
import csv
import hashlib
import ipaddress
import json
import re
import uuid

CSV_PATH = Path(__file__).resolve().parents[1] / 'data' / 'kql-lab-events.csv'
EXPECTED_SHA256 = '6867f140de9f28ebdc7cee0fd7ae9cf3300aef6a6f3656b4e0d3fc540740933f'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    checksum = hashlib.sha256(CSV_PATH.read_bytes()).hexdigest()
    require(checksum == EXPECTED_SHA256, 'CSV checksum differs from the documented snapshot')
    with CSV_PATH.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        require(len(reader.fieldnames) == 23, 'Expected 23 columns')
        rows = list(reader)
    require(len(rows) == 367, 'Expected 367 records')
    require(len({r['LabEventId'] for r in rows}) == 367, 'Duplicate source identifiers')
    require(all(r['IsSynthetic'].lower() == 'true' for r in rows), 'Unexpected provenance value')
    for row in rows:
        row['_time'] = datetime.fromisoformat(row['TimeGenerated'].replace('Z', '+00:00'))
    require(min(r['_time'] for r in rows).isoformat() == '2026-09-24T07:00:00+00:00', 'Unexpected first timestamp')
    require(max(r['_time'] for r in rows).isoformat() == '2026-09-30T15:01:00+00:00', 'Unexpected last timestamp')
    event_counts = Counter((r['EventSource'], r['EventID']) for r in rows)
    require(event_counts == {('WindowsSecurity', '4624'): 65, ('WindowsSecurity', '4625'): 37, ('WindowsSecurity', '4720'): 3, ('Sysmon', '1'): 131, ('Sysmon', '3'): 131}, 'Unexpected event totals')

    failures = [r for r in rows if r['EventSource'] == 'WindowsSecurity' and r['EventID'] == '4625']
    clusters = Counter((r['Computer'], r['TargetDomainName'], r['TargetUserName'], r['SourceIp'], r['_time'].replace(minute=(r['_time'].minute // 10) * 10, second=0, microsecond=0)) for r in failures)
    qualified = [n for n in clusters.values() if n >= 5]
    require(sorted(qualified) == [6, 7], 'Failed-logon groups differ')
    detail_failures = [r for r in failures if '2026-09-30T09:00:00Z' <= r['TimeGenerated'] < '2026-09-30T11:20:00Z' and r['SourceIp'] in ('10.0.0.50', '10.0.0.60')]
    require(len(detail_failures) == 13, 'Failure-detail count differs')
    require(all(r['SubStatus'] == '0xC000006A' for r in detail_failures), 'Unexpected failure substatus')
    keys = ('Computer', 'TargetDomainName', 'TargetUserName', 'SourceIp', 'LogonType')
    successes = [r for r in rows if r['EventSource'] == 'WindowsSecurity' and r['EventID'] == '4624']
    correlated = []
    for success in successes:
        count = sum(all(f[k] == success[k] for k in keys) and success['_time'] - timedelta(minutes=10) <= f['_time'] < success['_time'] for f in failures)
        if count >= 5:
            correlated.append((success['LabEventId'], success['TargetUserName'], count))
    require(correlated == [('LAB-000329', 'alex', 6)], 'Failure-to-success correlation differs')
    account_creations = [r for r in rows if r['EventSource'] == 'WindowsSecurity' and r['EventID'] == '4720']
    local_creations = [r for r in account_creations if r['TargetDomainName'].casefold() == r['Computer'].casefold()]
    require(len(account_creations) == 3 and sorted(r['TargetUserName'] for r in local_creations) == ['svc_support', 'testuser'], 'Account creation results differ')
    processes = [r for r in rows if r['EventSource'] == 'Sysmon' and r['EventID'] == '1']
    encoded = [r for r in processes if r['Image'].lower().endswith('\\powershell.exe') and re.search(r'(?i)(^|\s)-(encodedcommand|enc)\s', r['CommandLine'])]
    decoded = []
    for r in encoded:
        match = re.search(r'(?i)(?:^|\s)-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]+)', r['CommandLine'])
        require(match is not None, 'Missing encoded payload')
        decoded.append(base64.b64decode(match.group(1), validate=True).decode('utf-16le'))
    require(sorted(decoded) == ["Write-Output 'Approved maintenance check'", "Write-Output 'KQL-Lab-Demo'"], 'Decoded texts differ')
    process_counts = Counter((r['Computer'], r['Image']) for r in processes)
    rare_paths = {key for key, n in process_counts.items() if n == 1}
    require(rare_paths == {('WIN11-01', r'C:\Users\alex\AppData\Local\Temp\sync-helper.exe'), ('WIN11-02', r'C:\Windows\System32\whoami.exe')}, 'Rare process results differ')
    private_ranges = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    selected_network = []
    for r in rows:
        if r['EventSource'] != 'Sysmon' or r['EventID'] != '3' or r['Initiated'].lower() != 'true':
            continue
        try:
            address = ipaddress.IPv4Address(r['DestinationIp'])
        except ipaddress.AddressValueError:
            continue
        if not any(address in network for network in private_ranges):
            selected_network.append(r)
    destination_counts = Counter((r['DestinationIp'], int(r['DestinationPort']), r['Protocol']) for r in selected_network)
    rare_destinations = {key: n for key, n in destination_counts.items() if n <= 3}
    require(rare_destinations == {('203.0.113.25', 443, 'tcp'): 1, ('198.51.100.77', 4444, 'tcp'): 3}, 'Rare destination results differ')
    helper = [r for r in processes if r['LabEventId'] == 'LAB-000335'][0]
    helper_guid = str(uuid.UUID(helper['ProcessGuid']))
    helper_connections = [r for r in selected_network if r['DestinationIp'] == '198.51.100.77' and int(r['DestinationPort']) == 4444 and r['Computer'] == helper['Computer'] and str(uuid.UUID(r['ProcessGuid'])) == helper_guid and r['_time'] >= helper['_time']]
    require([r['LabEventId'] for r in helper_connections] == ['LAB-000337', 'LAB-000338', 'LAB-000339'], 'Process/network matches differ')
    require([r['_time'].strftime('%H:%M:%S') for r in helper_connections] == ['09:10:10', '09:11:10', '09:12:10'], 'Network timestamps differ')
    print(json.dumps({'status': 'passed', 'records': len(rows), 'columns': 23, 'sha256': checksum, 'headline_hunt_rows': [len(qualified), len(correlated), len(local_creations), len(encoded), len(rare_paths), len(rare_destinations)], 'process_correlated_network_rows': len(helper_connections), 'decoded_commands': decoded, 'scope': 'CSV checks only; original KQL was validated separately in ADX'}, indent=2))


if __name__ == '__main__':
    main()
