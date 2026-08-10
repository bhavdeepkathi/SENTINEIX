from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.models.log_event import LogEvent
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.schemas.alert import AlertCreate


class RuleEngine:
    """
    Simple rule-based detection.
    Each rule inspects recent log events and creates alerts.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def run_all_rules(self, since_minutes: int = 60) -> List[Alert]:
        alerts = []
        alerts.extend(await self._rule_repeated_failed_logins(since_minutes))
        alerts.extend(await self._rule_impossible_login(since_minutes))
        alerts.extend(await self._rule_privilege_escalation(since_minutes))
        alerts.extend(await self._rule_suspicious_powershell(since_minutes))
        alerts.extend(await self._rule_large_data_transfer(since_minutes))
        alerts.extend(await self._rule_malware_indicator(since_minutes))
        return alerts

    async def _create_alert(self, title: str, description: str, severity: AlertSeverity,
                            source_event: LogEvent) -> Alert:
        alert = Alert(
            title=title,
            description=description,
            severity=severity,
            status=AlertStatus.open,
            source_event_id=source_event.id,
        )
        self.db.add(alert)
        await self.db.flush()
        return alert

    # Rule 1: Repeated failed logins (>=5 failures for same user within window)
    async def _rule_repeated_failed_logins(self, since_minutes: int) -> List[Alert]:
        alerts = []
        window_start = datetime.utcnow() - timedelta(minutes=since_minutes)
        stmt = (
            select(LogEvent.username, LogEvent.source_ip, func.count(LogEvent.id).label("cnt"))
            .where(
                and_(
                    LogEvent.timestamp >= window_start,
                    LogEvent.event_type == "login_failed",
                    LogEvent.username.is_not(None),
                )
            )
            .group_by(LogEvent.username, LogEvent.source_ip)
            .having(func.count(LogEvent.id) >= 5)
        )
        result = await self.db.execute(stmt)
        for username, src_ip, cnt in result.all():
            # find a representative event
            ev_stmt = select(LogEvent).where(
                and_(
                    LogEvent.username == username,
                    LogEvent.source_ip == src_ip,
                    LogEvent.event_type == "login_failed",
                    LogEvent.timestamp >= window_start,
                )
            ).order_by(LogEvent.timestamp.desc()).limit(1)
            ev_res = await self.db.execute(ev_stmt)
            ev = ev_res.scalar_one_or_none()
            if ev:
                alert = await self._create_alert(
                    title="Repeated Failed Logins",
                    description=f"User {username} from {src_ip} had {cnt} failed login attempts in the last {since_minutes} minutes.",
                    severity=AlertSeverity.medium,
                    source_event=ev,
                )
                alerts.append(alert)
        return alerts

    # Rule 2: Impossible login (same user from two distant IPs within short time)
    async def _rule_impossible_login(self, since_minutes: int) -> List[Alert]:
        alerts = []
        window_start = datetime.utcnow() - timedelta(minutes=since_minutes)
        # successful logins
        stmt = select(LogEvent).where(
            and_(
                LogEvent.timestamp >= window_start,
                LogEvent.event_type == "login_success",
                LogEvent.username.is_not(None),
                LogEvent.source_ip.is_not(None),
            )
        ).order_by(LogEvent.username, LogEvent.timestamp)
        result = await self.db.execute(stmt)
        events = result.scalars().all()
        # group by user
        from collections import defaultdict
        by_user: Dict[str, List[LogEvent]] = defaultdict(list)
        for ev in events:
            by_user[ev.username].append(ev)
        for user, evs in by_user.items():
            # check pairwise distinct IPs within 10 minutes
            for i in range(len(evs)):
                for j in range(i + 1, len(evs)):
                    if evs[i].source_ip != evs[j].source_ip:
                        time_diff = abs((evs[i].timestamp - evs[j].timestamp).total_seconds())
                        if time_diff <= 600:  # 10 minutes
                            alert = await self._create_alert(
                                title="Impossible Login",
                                description=f"User {user} logged in from {evs[i].source_ip} and {evs[j].source_ip} within {time_diff:.0f} seconds.",
                                severity=AlertSeverity.high,
                                source_event=evs[i],
                            )
                            alerts.append(alert)
        return alerts

    # Rule 3: Privilege escalation events
    async def _rule_privilege_escalation(self, since_minutes: int) -> List[Alert]:
        alerts = []
        window_start = datetime.utcnow() - timedelta(minutes=since_minutes)
        stmt = select(LogEvent).where(
            and_(
                LogEvent.timestamp >= window_start,
                LogEvent.event_type == "privilege_escalation",
            )
        )
        result = await self.db.execute(stmt)
        for ev in result.scalars().all():
            alert = await self._create_alert(
                title="Privilege Escalation Detected",
                description=f"Privilege escalation event on host {ev.hostname or 'unknown'} by user {ev.username or 'unknown'}.",
                severity=AlertSeverity.high,
                source_event=ev,
            )
            alerts.append(alert)
        return alerts

    # Rule 4: Suspicious PowerShell execution
    async def _rule_suspicious_powershell(self, since_minutes: int) -> List[Alert]:
        alerts = []
        window_start = datetime.utcnow() - timedelta(minutes=since_minutes)
        stmt = select(LogEvent).where(
            and_(
                LogEvent.timestamp >= window_start,
                LogEvent.event_type == "process_creation",
                LogEvent.action.ilike("%powershell%"),
            )
        )
        result = await self.db.execute(stmt)
        for ev in result.scalars().all():
            # simple heuristic: encoded command or bypass
            if ev.raw_message and ("-enc" in ev.raw_message.lower() or "bypass" in ev.raw_message.lower()):
                sev = AlertSeverity.high
            else:
                sev = AlertSeverity.medium
            alert = await self._create_alert(
                title="Suspicious PowerShell Execution",
                description=f"PowerShell execution on {ev.hostname or 'unknown'} by {ev.username or 'unknown'}.",
                severity=sev,
                source_event=ev,
            )
            alerts.append(alert)
        return alerts

    # Rule 5: Large data transfer (e.g., >100MB in a single event)
    async def _rule_large_data_transfer(self, since_minutes: int) -> List[Alert]:
        alerts = []
        window_start = datetime.utcnow() - timedelta(minutes=since_minutes)
        stmt = select(LogEvent).where(
            and_(
                LogEvent.timestamp >= window_start,
                LogEvent.event_type == "data_transfer",
            )
        )
        result = await self.db.execute(stmt)
        for ev in result.scalars().all():
            # try to extract size from raw_message (assuming key=value size=)
            size = 0
            if ev.raw_message:
                import re
                m = re.search(r'size=(\d+)', ev.raw_message)
                if m:
                    size = int(m.group(1))
            if size > 100 * 1024 * 1024:  # 100 MB
                alert = await self._create_alert(
                    title="Large Data Transfer",
                    description=f"Data transfer of {size/1024/1024:.1f} MB from {ev.source_ip} to {ev.destination_ip}.",
                    severity=AlertSeverity.high,
                    source_event=ev,
                )
                alerts.append(alert)
        return alerts

    # Rule 6: Malware indicator (simple keyword match)
    async def _rule_malware_indicator(self, since_minutes: int) -> List[Alert]:
        alerts = []
        window_start = datetime.utcnow() - timedelta(minutes=since_minutes)
        malware_keywords = ["mimikatz", "cobaltstrike", "meterpreter", "empire", "sharpkatz"]
        stmt = select(LogEvent).where(
            and_(
                LogEvent.timestamp >= window_start,
                LogEvent.raw_message.is_not(None),
            )
        )
        result = await self.db.execute(stmt)
        for ev in result.scalars().all():
            lowered = ev.raw_message.lower()
            for kw in malware_keywords:
                if kw in lowered:
                    alert = await self._create_alert(
                        title="Malware Indicator",
                        description=f"Potential malware tool '{kw}' referenced in log on {ev.hostname or 'unknown'}.",
                        severity=AlertSeverity.critical,
                        source_event=ev,
                    )
                    alerts.append(alert)
                    break
        return alerts