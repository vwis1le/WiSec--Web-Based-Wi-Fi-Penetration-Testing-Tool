import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from database import get_db

REPORTS_DIR = os.path.join('static', 'reports')


def cvss_to_severity(score):
    """Derive qualitative severity from a CVSS v3.1 numeric score"""
    if score >= 9.0:
        return 'Critical'
    elif score >= 7.0:
        return 'High'
    elif score >= 4.0:
        return 'Medium'
    elif score > 0.0:
        return 'Low'
    return 'None'


def severity_color(severity):
    return {
        'Critical': colors.HexColor('#7A0C2E'),
        'High': colors.HexColor('#A32D2D'),
        'Medium': colors.HexColor('#854F0B'),
        'Low': colors.HexColor('#1D9E75'),
        'None': colors.HexColor('#484f58'),
    }.get(severity, colors.HexColor('#484f58'))


def generate_report(scan_id):
    """Generate a PDF report for a completed scan and store its path in the database"""
    db = get_db()

    scan = db.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,)).fetchone()
    if not scan:
        db.close()
        raise ValueError(f'No scan found with scan_id {scan_id}')

    vulns = db.execute('''
        SELECT v.*, vt.type as vuln_type, r.recommendation
        FROM vulnerabilities v
        JOIN vulnerability_type vt ON v.vulntype_id = vt.vulntype_id
        LEFT JOIN recommendations r ON v.vuln_id = r.vuln_id
        WHERE v.scan_id = ?
        ORDER BY v.cvss_score DESC
    ''', (scan_id,)).fetchall()

    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f'wisec_report_scan{scan_id}_{datetime.now().strftime("%Y%m%d%H%M%S")}.pdf'
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        filepath, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'WiSecTitle', parent=styles['Title'], fontSize=22,
        textColor=colors.HexColor('#0C447C'), spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'WiSecSubtitle', parent=styles['Normal'], fontSize=11,
        textColor=colors.HexColor('#484f58'), spaceAfter=20
    )
    section_style = ParagraphStyle(
        'WiSecSection', parent=styles['Heading2'], fontSize=14,
        textColor=colors.HexColor('#0C447C'), spaceBefore=16, spaceAfter=8
    )
    body_style = styles['Normal']

    story = []

    # Header
    story.append(Paragraph('WiSec — Wi-Fi Penetration Test Report', title_style))
    story.append(Paragraph(
        f'Target network: {scan["network_name"]}<br/>'
        f'Scan date: {scan["timestamp"]}<br/>'
        f'Modules run: {scan["modules_run"]}<br/>'
        f'Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        subtitle_style
    ))

    # Executive summary
    story.append(Paragraph('Executive Summary', section_style))
    total_vulns = len(vulns)
    if total_vulns == 0:
        summary_text = (
            'No vulnerabilities were identified during this assessment based on the '
            'modules executed. This does not guarantee the absence of all security '
            'issues; it reflects the scope and modules selected for this scan.'
        )
    else:
        severities = [cvss_to_severity(v['cvss_score']) for v in vulns]
        counts = {s: severities.count(s) for s in ['Critical', 'High', 'Medium', 'Low']}
        summary_text = (
            f'This assessment identified {total_vulns} vulnerabilit'
            f'{"y" if total_vulns == 1 else "ies"} across the tested network. '
            f'Severity breakdown: {counts["Critical"]} Critical, {counts["High"]} High, '
            f'{counts["Medium"]} Medium, {counts["Low"]} Low. '
            'Findings are detailed below in descending order of CVSS severity, '
            'along with remediation guidance for each.'
        )
    story.append(Paragraph(summary_text, body_style))

    # Findings table
    story.append(Paragraph('Detailed Findings', section_style))

    if total_vulns == 0:
        story.append(Paragraph('No findings to report for this scan.', body_style))
    else:
        table_data = [['Vulnerability', 'Severity', 'CVSS', 'Description']]
        for v in vulns:
            severity = cvss_to_severity(v['cvss_score'])
            table_data.append([
                Paragraph(v['vuln_type'], body_style),
                severity,
                f'{v["cvss_score"]:.1f}',
                Paragraph(v['description'] or '', body_style)
            ])

        col_widths = [1.4 * inch, 0.8 * inch, 0.6 * inch, 2.9 * inch]
        table = Table(table_data, colWidths=col_widths, repeatRows=1)

        style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0C447C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#30363d')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f7fa')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]
        for i, v in enumerate(vulns, start=1):
            sev_color = severity_color(cvss_to_severity(v['cvss_score']))
            style_commands.append(('TEXTCOLOR', (1, i), (1, i), sev_color))
            style_commands.append(('FONTNAME', (1, i), (1, i), 'Helvetica-Bold'))

        table.setStyle(TableStyle(style_commands))
        story.append(table)

    # Recommendations
    if total_vulns > 0:
        story.append(PageBreak())
        story.append(Paragraph('Remediation Recommendations', section_style))
        for v in vulns:
            severity = cvss_to_severity(v['cvss_score'])
            heading = Paragraph(
                f'<b>{v["vuln_type"]}</b> '
                f'<font color="{severity_color(severity).hexval()}">[{severity}, CVSS {v["cvss_score"]:.1f}]</font>',
                body_style
            )
            story.append(heading)
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                v['recommendation'] or 'Consult a cybersecurity professional for remediation advice.',
                body_style
            ))
            story.append(Spacer(1, 12))

    # Footer note
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        '<i>This report was generated automatically by the WiSec Wi-Fi penetration '
        'testing framework as part of an academic assessment. Findings should be '
        'verified by a qualified security professional before remediation in a '
        'production environment.</i>',
        ParagraphStyle('Footer', parent=body_style, fontSize=8, textColor=colors.HexColor('#484f58'))
    ))

    doc.build(story)

    # Store report record in database
    db.execute(
        'INSERT INTO reports (scan_id, pdf_path) VALUES (?, ?)',
        (scan_id, filepath)
    )
    db.commit()
    db.close()

    return filepath
