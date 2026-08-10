import csv
import json
import re
from datetime import datetime
from typing import List, Dict, Any
from app.schemas.log_event import LogEventCreate


class LogNormalizer:
    """
    Normalize various log formats into the unified LogEventCreate schema.
    Supported formats:
    - JSON (array of objects or newline-delimited JSON)
    - CSV (with header)
    - Linux auth.log style (syslog)
    - Windows Security event log (simplified)
    - Generic application log (key=value pairs)
    """

    # Common regex for syslog-like timestamps (e.g., "Jan 10 10:01:02")
    SYSLOG_TIMESTAMP = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

    @staticmethod
    def parse_json(content: str) -> List[LogEventCreate]:
        events = []
        # Try parse as JSON array
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    events.append(LogNormalizer._map_json(item))
            else:
                events.append(LogNormalizer._map_json(data))
        except json.JSONDecodeError:
            # Maybe newline-delimited JSON
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    events.append(LogNormalizer._map_json(item))
                except json.JSONDecodeError:
                    continue
        return events

    @staticmethod
    def _map_json(obj: Dict[str, Any]) -> LogEventCreate:
        # Map common fields, fallback to raw_message
        return LogEventCreate(
            timestamp=LogNormalizer._parse_timestamp(obj.get('timestamp') or obj.get('time') or obj.get('@timestamp')),
            source=obj.get('source', 'json'),
            event_type=obj.get('event_type') or obj.get('event') or obj.get('type', 'unknown'),
            username=obj.get('username') or obj.get('user') or obj.get('account'),
            source_ip=obj.get('source_ip') or obj.get('src_ip') or obj.get('clientip'),
            destination_ip=obj.get('destination_ip') or obj.get('dst_ip') or obj.get('dest_ip'),
            hostname=obj.get('hostname') or obj.get('host') or obj.get('computer'),
            action=obj.get('action') or obj.get('message') or obj.get('event_action'),
            status=obj.get('status') or obj.get('result') or obj.get('outcome'),
            severity=obj.get('severity') or obj.get('level') or obj.get('priority'),
            raw_message=json.dumps(obj)
        )

    @staticmethod
    def parse_csv(content: str) -> List[LogEventCreate]:
        events = []
        reader = csv.DictReader(content.splitlines())
        for row in reader:
            events.append(LogNormalizer._map_csv(row))
        return events

    @staticmethod
    def _map_csv(row: Dict[str, str]) -> LogEventCreate:
        # Try to find timestamp column (case-insensitive)
        timestamp_val = None
        for key in row:
            if key.lower() in ('timestamp', 'time', 'date', '@timestamp'):
                timestamp_val = row[key]
                break
        return LogEventCreate(
            timestamp=LogNormalizer._parse_timestamp(timestamp_val),
            source=row.get('source', 'csv'),
            event_type=row.get('event_type') or row.get('event') or row.get('type', 'unknown'),
            username=row.get('username') or row.get('user') or row.get('account'),
            source_ip=row.get('source_ip') or row.get('src_ip') or row.get('clientip'),
            destination_ip=row.get('destination_ip') or row.get('dst_ip') or row.get('dest_ip'),
            hostname=row.get('hostname') or row.get('host') or row.get('computer'),
            action=row.get('action') or row.get('message') or row.get('event_action'),
            status=row.get('status') or row.get('result') or row.get('outcome'),
            severity=row.get('severity') or row.get('level') or row.get('priority'),
            raw_message=json.dumps(row)
        )

    @staticmethod
    def parse_linux_auth(content: str) -> List[LogEventCreate]:
        events = []
        # Example line: "Jan 10 10:01:02 hostname sshd[1234]: Failed password for user1 from 192.168.1.1 port 22 ssh2"
        pattern = re.compile(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)$'
        )
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            if not m:
                continue
            timestamp_str, hostname, process, message = m.groups()
            # Parse timestamp assuming current year
            timestamp = LogNormalizer._parse_timestamp(timestamp_str)
            # Simple classification
            event_type = 'auth'
            username = None
            source_ip = None
            action = message
            status = 'unknown'
            severity = 'info'
            if 'Failed password' in message:
                event_type = 'login_failed'
                severity = 'medium'
                status = 'failure'
                # extract user and ip
                user_match = re.search(r'for (\S+) from', message)
                if user_match:
                    username = user_match.group(1)
                ip_match = re.search(r'from ([\d\.]+)', message)
                if ip_match:
                    source_ip = ip_match.group(1)
            elif 'Accepted password' in message:
                event_type = 'login_success'
                severity = 'info'
                status = 'success'
                user_match = re.search(r'for (\S+) from', message)
                if user_match:
                    username = user_match.group(1)
                ip_match = re.search(r'from ([\d\.]+)', message)
                if ip_match:
                    source_ip = ip_match.group(1)
            events.append(LogEventCreate(
                timestamp=timestamp,
                source='linux_auth',
                event_type=event_type,
                username=username,
                source_ip=source_ip,
                hostname=hostname,
                action=action,
                status=status,
                severity=severity,
                raw_message=line
            ))
        return events

    @staticmethod
    def parse_windows_security(content: str) -> List[LogEventCreate]:
        events = []
        # Simplified parsing for Windows Security Event Log (Event ID 4624, 4625, etc.)
        # Assume each line is a JSON representation of the event (as exported by wevtutil)
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                events.append(LogNormalizer._map_windows(obj))
            except json.JSONDecodeError:
                continue
        return events

    @staticmethod
    def _map_windows(obj: Dict[str, Any]) -> LogEventCreate:
        # Map common Windows event fields
        event_id = obj.get('EventID') or obj.get('EventId') or obj.get('id')
        event_type = 'windows_security'
        severity = 'info'
        status = 'unknown'
        if event_id == 4624:
            event_type = 'login_success'
            status = 'success'
        elif event_id == 4625:
            event_type = 'login_failed'
            severity = 'medium'
            status = 'failure'
        elif event_id == 4672:
            event_type = 'privilege_escalation'
            severity = 'high'
        elif event_id == 4688:
            event_type = 'process_creation'
        # Extract fields
        timestamp = LogNormalizer._parse_timestamp(obj.get('TimeCreated') or obj.get('TimeGenerated') or obj.get('timestamp'))
        username = obj.get('TargetUserName') or obj.get('SubjectUserName') or obj.get('User')
        source_ip = obj.get('IpAddress') or obj.get('IpPort') or obj.get('SourceNetworkAddress')
        hostname = obj.get('Computer') or obj.get('Hostname')
        action = obj.get('Message') or obj.get('EventData') or json.dumps(obj)
        return LogEventCreate(
            timestamp=timestamp,
            source='windows_security',
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            hostname=hostname,
            action=action,
            status=status,
            severity=severity,
            raw_message=json.dumps(obj)
        )

    @staticmethod
    def parse_generic(content: str) -> List[LogEventCreate]:
        events = []
        # Generic key=value pairs per line, e.g., "timestamp=2024-01-10T10:01:02Z source=app event_type=login username=user1 source_ip=1.2.3.4"
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            # Split by spaces but respect quoted values
            # Simple approach: split on whitespace, then each token key=value
            parts = line.split()
            kv = {}
            for part in parts:
                if '=' in part:
                    k, v = part.split('=', 1)
                    kv[k] = v
            if not kv:
                continue
            events.append(LogEventCreate(
                timestamp=LogNormalizer._parse_timestamp(kv.get('timestamp') or kv.get('time')),
                source=kv.get('source', 'generic'),
                event_type=kv.get('event_type') or kv.get('event') or kv.get('type', 'unknown'),
                username=kv.get('username') or kv.get('user'),
                source_ip=kv.get('source_ip') or kv.get('src_ip'),
                destination_ip=kv.get('destination_ip') or kv.get('dst_ip'),
                hostname=kv.get('hostname') or kv.get('host'),
                action=kv.get('action') or kv.get('message'),
                status=kv.get('status') or kv.get('result'),
                severity=kv.get('severity') or kv.get('level'),
                raw_message=line
            ))
        return events

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if value is None:
            return datetime.utcnow()
        if isinstance(value, datetime):
            return value
        # Try common formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%b %d %H:%M:%S',  # syslog without year
            '%d/%b/%Y:%H:%M:%S',  # apache
        ]
        for fmt in formats:
            try:
                return datetime.strptime(str(value), fmt)
            except ValueError:
                continue
        # Fallback: return now
        return datetime.utcnow()

    @classmethod
    def normalize(cls, content: str, fmt: str) -> List[LogEventCreate]:
        fmt = fmt.lower()
        if fmt == 'json':
            return cls.parse_json(content)
        elif fmt == 'csv':
            return cls.parse_csv(content)
        elif fmt in ('linux_auth', 'syslog'):
            return cls.parse_linux_auth(content)
        elif fmt in ('windows_security', 'winevt'):
            return cls.parse_windows_security(content)
        elif fmt == 'generic':
            return cls.parse_generic(content)
        else:
            # Try auto-detect: if starts with [ or { -> json, if contains commas and header -> csv, else generic
            stripped = content.lstrip()
            if stripped.startswith('{') or stripped.startswith('['):
                return cls.parse_json(content)
            elif ',' in stripped and '\n' in stripped:
                # maybe csv
                try:
                    return cls.parse_csv(content)
                except Exception:
                    pass
            # default generic
            return cls.parse_generic(content)