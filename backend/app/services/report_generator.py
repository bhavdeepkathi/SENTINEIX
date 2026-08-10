import os
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from typing import List, Dict, Any


def generate_incident_report(incident: Dict[str, Any],
                             timeline: List[Dict],
                             alerts: List[Dict],
                             evidence: List[Dict],
                             investigation: Dict[str, Any] | None,
                             mitre: List[Dict],
                             recommendations: List[Dict]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='TitleLarge', fontSize=18, leading=22, alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name='Heading2Custom', fontSize=13, leading=16, spaceBefore=12, spaceAfter=6, textColor=HexColor('#1f2937')))
    styles.add(ParagraphStyle(name='BodyCustom', fontSize=10, leading=13, spaceAfter=4))
    styles.add(ParagraphStyle(name='CodeCustom', fontSize=8, leading=10, fontName='Courier', backColor=HexColor('#f3f4f6'), borderPadding=4))

    story = []

    # Title
    story.append(Paragraph("SentinelX Incident Report", styles['TitleLarge']))
    story.append(Paragraph(f"Incident: {incident.get('title','')}", styles['Heading2Custom']))
    story.append(Spacer(1, 6))

    # Metadata table
    meta_data = [
        ["Incident ID", str(incident.get('id',''))],
        ["Severity", incident.get('severity','')],
        ["Status", incident.get('status','')],
        ["Risk Score", str(incident.get('risk_score',''))],
        ["Created", incident.get('created_at','')],
        ["Updated", incident.get('updated_at','')],
    ]
    t = Table(meta_data, colWidths=[1.5*inch, 4.5*inch])
    t.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, HexColor('#d1d5db')),
        ('BACKGROUND', (0,0), (0,-1), HexColor('#f3f4f6')),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # Description
    if incident.get('description'):
        story.append(Paragraph("Description", styles['Heading2Custom']))
        story.append(Paragraph(incident['description'], styles['BodyCustom']))
        story.append(Spacer(1, 8))

    # Timeline
    if timeline:
        story.append(Paragraph("Timeline", styles['Heading2Custom']))
        tl_data = [["#", "Time", "Source", "Event Type", "User", "IP", "Host", "Action", "Status", "Severity"]]
        for ev in timeline[:50]:  # limit rows
            tl_data.append([
                str(ev.get('sequence_no','')),
                ev.get('timestamp','')[:19].replace('T',' '),
                ev.get('source',''),
                ev.get('event_type',''),
                ev.get('username','') or '-',
                ev.get('source_ip','') or '-',
                ev.get('hostname','') or '-',
                (ev.get('action','') or '-')[:40],
                ev.get('status','') or '-',
                ev.get('severity','') or '-',
            ])
        t2 = Table(tl_data, repeatRows=1, colWidths=[0.3*inch, 1.0*inch, 0.7*inch, 0.8*inch, 0.6*inch, 0.7*inch, 0.6*inch, 1.0*inch, 0.5*inch, 0.5*inch])
        t2.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.4, HexColor('#d1d5db')),
            ('BACKGROUND', (0,0), (-1,0), HexColor('#1f2937')),
            ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
            ('FONTSIZE', (0,0), (-1,-1), 7),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t2)
        story.append(Spacer(1, 12))

    # Alerts
    if alerts:
        story.append(Paragraph("Alerts", styles['Heading2Custom']))
        al_data = [["ID", "Title", "Severity", "Status", "Created"]]
        for a in alerts:
            al_data.append([str(a.get('id','')), a.get('title',''), a.get('severity',''), a.get('status',''), a.get('created_at','')[:19]])
        t3 = Table(al_data, repeatRows=1, colWidths=[0.5*inch, 2.5*inch, 0.7*inch, 0.7*inch, 1.3*inch])
        t3.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.4, HexColor('#d1d5db')),
            ('BACKGROUND', (0,0), (-1,0), HexColor('#1f2937')),
            ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        story.append(t3)
        story.append(Spacer(1, 12))

    # Evidence
    if evidence:
        story.append(Paragraph("Evidence", styles['Heading2Custom']))
        ev_data = [["Filename", "Type", "Size (bytes)", "SHA256", "Uploaded"]]
        for e in evidence:
            ev_data.append([e.get('filename',''), e.get('file_type','') or '-', str(e.get('file_size','')), e.get('sha256','')[:32]+'...', e.get('uploaded_at','')[:19]])
        t4 = Table(ev_data, repeatRows=1, colWidths=[1.5*inch, 0.8*inch, 0.7*inch, 2.0*inch, 1.0*inch])
        t4.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.4, HexColor('#d1d5db')),
            ('BACKGROUND', (0,0), (-1,0), HexColor('#1f2937')),
            ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        story.append(t4)
        story.append(Spacer(1, 12))

    # AI Investigation
    if investigation:
        story.append(Paragraph("AI Investigation", styles['Heading2Custom']))
        story.append(Paragraph(f"Attack Type: {investigation.get('attack_type','')}", styles['BodyCustom']))
        story.append(Paragraph(f"Confidence: {investigation.get('confidence',0)*100:.0f}%", styles['BodyCustom']))
        story.append(Paragraph(f"Root Cause: {investigation.get('root_cause','')}", styles['BodyCustom']))
        story.append(Spacer(1, 6))
        # Attack sequence
        try:
            seq = investigation.get('attack_sequence')
            import json
            steps = json.loads(seq) if seq else []
            if steps:
                story.append(Paragraph("Attack Sequence:", styles['BodyCustom']))
                for i, step in enumerate(steps, 1):
                    story.append(Paragraph(f"{i}. {step}", styles['BodyCustom']))
        except Exception:
            pass
        story.append(Spacer(1, 8))

    # MITRE
    if mitre:
        story.append(Paragraph("MITRE ATT&CK Mapping", styles['Heading2Custom']))
        m_data = [["Technique ID", "Name", "Tactic", "Confidence", "Evidence Ref"]]
        for m in mitre:
            m_data.append([m.get('technique_id',''), m.get('name',''), m.get('tactic',''), f"{m.get('confidence',0)*100:.0f}%", m.get('evidence_ref','') or '-'])
        t5 = Table(m_data, repeatRows=1, colWidths=[1.0*inch, 1.5*inch, 1.0*inch, 0.7*inch, 1.5*inch])
        t5.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.4, HexColor('#d1d5db')),
            ('BACKGROUND', (0,0), (-1,0), HexColor('#1f2937')),
            ('TEXTCOLOR', (0,0), (-1,0), HexColor('#ffffff')),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        story.append(t5)
        story.append(Spacer(1, 12))

    # Recommendations
    if recommendations:
        story.append(Paragraph("Recommendations", styles['Heading2Custom']))
        for r in recommendations:
            story.append(Paragraph(f"• {r.get('description','')} (Priority: {r.get('priority','medium')})", styles['BodyCustom']))
        story.append(Spacer(1, 12))

    # Footer
    story.append(Spacer(1, 24))
    story.append(Paragraph(f"Report generated at {datetime.utcnow().isoformat()}Z by SentinelX", styles['BodyCustom']))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()