"""
HTML Report Generator for Vexa.

SS-006: Human-readable HTML report with Jinja2 templating.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from vexa.reports.generator import BaseReportGenerator, ReportGenerator, ReportMetadata
from vexa.scanners.base import Finding
from vexa.scanners.engine import ScanResult
from vexa.security.output_sanitizer import OutputSanitizer
from vexa.common.logging import get_logger
import markdown


logger = get_logger(__name__)


class HTMLReportGenerator(BaseReportGenerator):
    """
    SS-006: HTML report generator for human review.

    Produces professional HTML reports with:
    - Executive summary
    - Severity breakdown
    - Finding details with code snippets
    - Responsive design
    """

    format_name = "html"
    file_extension = ".html"

    # Severity colors
    SEVERITY_COLORS = {
        "critical": "#dc2626",  # Red-600
        "high": "#ea580c",  # Orange-600
        "medium": "#ca8a04",  # Yellow-600
        "low": "#2563eb",  # Blue-600
        "info": "#6b7280",  # Gray-500
    }

    def generate(
        self,
        result: ScanResult,
        output_path: Path,
        metadata: Optional[ReportMetadata] = None,
    ) -> Path:
        """Generate HTML report."""
        output_path = self._prepare_output_path(output_path)
        metadata = metadata or ReportMetadata()

        sanitizer = OutputSanitizer()

        html_content = self._render_report(result, metadata, sanitizer)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _render_markdown(self, content: str, sanitizer: OutputSanitizer) -> str:
        """Render markdown content safely."""
        if not content:
            return ""
        # Sanitize first to prevent XSS from raw HTML
        safe_text = sanitizer.escape_html(content)
        # Convert escaped blockquotes back to allow markdown processing
        # This is a safe subset allowing blockquotes
        safe_text = safe_text.replace("&gt; ", "> ")

        # Preprocess: Ensure headers have newlines before them if they are stuck to text
        # Example: "Summary text ### Impact" -> "Summary text\n\n### Impact"
        # Handle start of string and mid-text
        safe_text = re.sub(r"(^|[^#\n])\s*(#{1,6}\s)", r"\1\n\n\2", safe_text)

        # Clean up: Remove any empty header artifacts (e.g., # \n)
        safe_text = re.sub(r"^#{1,6}\s*$", "", safe_text, flags=re.MULTILINE)

        # Render markdown
        try:
            # extra: tables, fenced codes, etc.
            # codehilite: code highlighting
            html_out = markdown.markdown(safe_text, extensions=["extra", "codehilite"])
            # Final polish: Remove empty tags like <h1></h1> if they were generated
            html_out = re.sub(r"<h[1-6]>\s*</h[1-6]>", "", html_out)
            return html_out
        except Exception as e:
            logger.warning(f"Markdown rendering failed: {e}")
            return safe_text

    def _render_report(
        self,
        result: ScanResult,
        metadata: ReportMetadata,
        sanitizer: OutputSanitizer,
    ) -> str:
        """Render the HTML report."""
        severity_counts = self._get_severity_counts(result.findings)
        scanner_counts = self._get_scanner_counts(result.findings)

        # Calculate Health Index
        health_index = self._calculate_health_index(severity_counts)

        # Build findings HTML
        findings_html = self._render_findings(result.findings, sanitizer)

        # Build the complete HTML
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{sanitizer.escape_html(metadata.title)}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: #0f172a;
            --secondary: #3b82f6;
            --accent: #6366f1;
            --bg: #f8fafc;
            --card-bg: rgba(255, 255, 255, 0.95);
            --text-main: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #94a3b8;
            --success: #10b981;
            --shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: 'Inter', system-ui, sans-serif; 
            line-height: 1.6; 
            color: var(--text-main); 
            background: var(--bg); 
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.05) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(59, 130, 246, 0.05) 0px, transparent 50%);
            padding-bottom: 60px;
        }}

        h1, h2, h3, h4 {{ font-family: 'Outfit', sans-serif; }}

        .container {{ max-width: 1200px; margin: 0 auto; padding: 0 40px; }}

        /* Header Area */
        header {{ 
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 20px 0;
            margin-bottom: 40px;
            position: sticky;
            top: 0;
            z-index: 1000;
        }}
        .header-content {{ display: flex; justify-content: space-between; align-items: center; }}
        header h1 {{ 
            font-size: 1.75rem; 
            font-weight: 700; 
            color: var(--primary); 
            display: flex; 
            align-items: center; 
            gap: 12px;
            letter-spacing: -0.02em;
        }}
        .header-meta {{ font-size: 0.85rem; color: var(--text-muted); text-align: right; }}
        
        /* Dashboard Summary */
        .dashboard {{ 
            display: grid; 
            grid-template-columns: 350px 1fr; 
            gap: 30px; 
            margin-bottom: 48px;
        }}

        .summary-card {{ 
            background: var(--card-bg); 
            border: 1px solid var(--border); 
            border-radius: 20px; 
            padding: 30px; 
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
        }}
        .summary-card:hover {{ box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); }}
        
        .summary-card h2 {{ 
            font-size: 1.1rem; 
            margin-bottom: 24px; 
            color: var(--text-muted); 
            text-transform: uppercase; 
            letter-spacing: 0.1em;
            font-weight: 600;
        }}

        .stats-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
        .stat-item {{ 
            padding: 20px; 
            border-radius: 16px; 
            background: #ffffff; 
            border: 1px solid var(--border); 
            text-align: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }}
        .stat-value {{ font-size: 2rem; font-weight: 700; color: var(--primary); display: block; font-family: 'Outfit'; }}
        .stat-label {{ font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; }}

        /* Severity Distribution */
        .severity-chart {{ display: flex; flex-direction: column; gap: 16px; }}
        .severity-row {{ display: grid; grid-template-columns: 100px 1fr 40px; align-items: center; gap: 20px; }}
        .severity-name {{ font-size: 0.9rem; font-weight: 600; color: var(--text-main); }}
        .progress-bg {{ height: 10px; background: #eef2f6; border-radius: 10px; overflow: hidden; position: relative; }}
        .progress-bar {{ position: absolute; left: 0; top: 0; height: 100%; border-radius: 10px; transition: width 1.5s cubic-bezier(0.4, 0, 0.2, 1); }}
        .count-pill {{ font-size: 0.9rem; font-weight: 700; color: var(--primary); text-align: right; }}

        /* Findings Area */
        .findings-section-header {{ 
            margin-bottom: 32px;
            padding-bottom: 16px;
            border-bottom: 2px solid var(--primary);
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}
        .findings-section-header h2 {{ font-size: 1.75rem; font-weight: 800; color: var(--primary); letter-spacing: -0.01em; }}

        .finding-card {{ 
            background: var(--card-bg); 
            border: 1px solid var(--border); 
            border-radius: 24px; 
            margin-bottom: 32px; 
            overflow: hidden; 
            box-shadow: var(--shadow);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        .finding-card:hover {{ transform: translateY(-4px); box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.15); }}
        
        .finding-header {{ 
            padding: 28px 32px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            background: linear-gradient(to right, #ffffff, #f8fafc);
            border-bottom: 1px solid var(--border);
        }}
        .finding-info {{ flex: 1; }}
        .finding-title {{ font-size: 1.25rem; font-weight: 700; color: var(--primary); margin-bottom: 8px; display: block; font-family: 'Outfit'; }}
        .finding-meta {{ font-size: 0.85rem; color: var(--text-muted); display: flex; gap: 20px; font-weight: 500; font-family: 'Inter', sans-serif; }}
        .scanner-badge {{ font-family: 'Outfit', sans-serif; font-weight: 700; color: var(--primary); letter-spacing: 0.05em; }}
        
        .severity-badge {{ 
            padding: 6px 16px; 
            border-radius: 100px; 
            font-size: 0.7rem; 
            font-weight: 700; 
            text-transform: uppercase; 
            color: white; 
            letter-spacing: 0.1em;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        .finding-body {{ padding: 32px; background: #ffffff; }}
        .finding-description {{ font-size: 0.95rem; margin-bottom: 30px; color: #334155; line-height: 1.7; white-space: pre-wrap; word-break: break-word; font-family: 'Inter', sans-serif; }}
        
        .code-block-container {{ margin-bottom: 30px; border-radius: 16px; overflow: hidden; border: 1px solid var(--border); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }}
        .code-header {{ 
            background: #f1f5f9; 
            padding: 12px 20px; 
            font-size: 0.75rem; 
            font-weight: 700; 
            color: var(--text-muted); 
            display: flex; 
            justify-content: space-between; 
            border-bottom: 1px solid var(--border); 
        }}
        .code-snippet {{ 
            background: #0f172a; 
            color: #f8fafc; 
            padding: 24px; 
            font-family: 'Fira Code', monospace; 
            font-size: 0.85rem; 
            overflow-x: auto; 
            line-height: 1.6;
        }}
        .remediation-snippet {{ background: #f0fdf4; color: #166534; border-top: 2px solid #22c55e; }}

        /* AI Enhancement Grid */
        .enhancement-grid {{ 
            display: grid; 
            grid-template-columns: repeat(2, 1fr); 
            gap: 24px; 
            margin-top: 32px; 
            padding-top: 32px; 
            border-top: 1px solid var(--border);
        }}
        .enhancement-box {{ 
            padding: 24px; 
            border-radius: 20px; 
            border: 1px solid var(--border);
            background: #fcfcfd;
            height: 100%;
            transition: all 0.2s ease;
        }}
        .enhancement-box:hover {{ background: #f8fafc; border-color: var(--secondary); }}
        .enhancement-box h4 {{ 
            font-size: 0.9rem; 
            font-weight: 700; 
            margin-bottom: 16px; 
            display: flex; 
            align-items: center; 
            gap: 10px; 
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--primary);
        }}
        .enhancement-content {{ font-size: 0.95rem; color: #475569; line-height: 1.7; font-family: 'Inter', sans-serif; }}

        /* Health Score */
        .health-index-container {{ position: relative; width: 150px; height: 150px; margin: 0 auto 20px; }}
        .health-circle-svg {{ width: 100%; height: 100%; transform: rotate(-90deg); }}
        .health-circle-bg {{ fill: none; stroke: #f1f5f9; stroke-width: 3.5; }}
        .health-circle-progress {{ 
            fill: none; 
            stroke-width: 3.5; 
            stroke-linecap: round; 
            transition: stroke-dashoffset 2s cubic-bezier(0.4, 0, 0.2, 1); 
        }}
        .health-value {{ 
            position: absolute; 
            top: 50%; 
            left: 50%; 
            transform: translate(-50%, -50%); 
            font-size: 2.25rem; 
            font-weight: 800; 
            color: var(--primary);
            font-family: 'Outfit';
        }}

        .tags {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 24px; }}
        .tag {{ 
            padding: 4px 14px; 
            background: #ffffff; 
            border: 1px solid var(--border); 
            border-radius: 100px; 
            font-size: 0.75rem; 
            font-weight: 600; 
            color: var(--text-muted);
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }}

        footer {{ 
            margin-top: 80px; 
            text-align: center; 
            color: var(--text-muted); 
            font-size: 0.9rem; 
            padding: 40px 0; 
            background: #ffffff;
            border-top: 1px solid var(--border);
        }}
        
        .toc-container {{
            background: rgba(255, 255, 255, 0.7);
            backdrop-filter: blur(8px);
            padding: 24px;
            border-radius: 20px;
            border: 1px solid var(--border);
            margin-bottom: 40px;
        }}
        .toc-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }}
        .toc-item {{
            text-decoration: none;
            font-size: 0.8rem;
            padding: 10px 15px;
            border-radius: 12px;
            background: white;
            border: 1px solid var(--border);
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.2s ease;
        }}
        .toc-item:hover {{ border-color: var(--secondary); transform: translateX(4px); }}

    </style>
</head>
<body>
    <header>
        <div class="container header-content">
            <h1>🛡️ VEXA <span style="font-weight: 300; color: var(--text-muted); font-size: 1.1rem; margin-left: 10px; letter-spacing: 0.1em;">ADVANCED SECURITY AUDIT</span></h1>
            <div class="header-meta">
                <div><strong>Target:</strong> {sanitizer.escape_html(metadata.scan_target or "N/A")}</div>
                <div><strong>Generated:</strong> {metadata.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
            </div>
        </div>
    </header>

    <div class="container">
        <div class="dashboard">
            <div class="summary-card" style="text-align: center;">
                <h2>System Health</h2>
                <div class="health-index-container">
                    <svg class="health-circle-svg" viewBox="0 0 36 36">
                        <path class="health-circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                        <path class="health-circle-progress" stroke-dasharray="{health_index}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                              style="stroke: {self._get_health_color(health_index)};" />
                    </svg>
                    <div class="health-value">{health_index}</div>
                </div>
                <div style="font-size: 1rem; font-weight: 800; color: {self._get_health_color(health_index)}; text-transform: uppercase; letter-spacing: 0.1em; margin-top: -10px; margin-bottom: 5px;">
                    {self._get_health_label(health_index)}
                </div>
                <div class="stat-label" style="letter-spacing: 0.2em; margin-bottom: 24px; font-size: 0.7rem;">Security Health Index</div>
                
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-value">{result.total_findings}</span>
                        <span class="stat-label">Total Issues</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value" style="color: var(--critical);">{severity_counts.get("high", 0) + severity_counts.get("critical", 0)}</span>
                        <span class="stat-label">Critical Risks</span>
                    </div>
                </div>

                <!-- Scoring Legend -->
                <div style="margin-top: 25px; padding-top: 15px; border-top: 1px dashed var(--border); font-size: 0.65rem; color: var(--text-muted); text-align: left;">
                    <div style="margin-bottom: 5px; font-weight: 700; text-transform: uppercase;">Scoring Legend:</div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <span><span style="color: #10b981;">●</span> 90-100 Exc.</span>
                        <span><span style="color: #f59e0b;">●</span> 70-89 Good</span>
                        <span><span style="color: #f97316;">●</span> 40-69 Fair</span>
                        <span><span style="color: #ef4444;">●</span> 0-39 Poor</span>
                    </div>
                </div>
            </div>

            <div class="summary-card">
                <h2>Risk Distribution</h2>
                <div class="severity-chart">
                    {self._render_severity_distribution(severity_counts, result.total_findings)}
                </div>
                
                <div style="margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                    <div class="header-meta" style="text-align: left; display: flex; gap: 32px;">
                        <div><strong style="color: var(--primary);">Job ID:</strong> {sanitizer.escape_html(metadata.job_id or "N/A")}</div>
                        <div><strong style="color: var(--primary);">Time:</strong> {result.duration_seconds:.2f}s</div>
                    </div>
                    <div style="font-size: 0.75rem; font-weight: 800; color: white; background: var(--primary); padding: 4px 12px; border-radius: 6px;">v{metadata.tool_version}</div>
                </div>
            </div>
        </div>

        {self._render_toc(result.findings, sanitizer)}

        <div class="findings-section-header">
            <h2>Detailed Findings</h2>
            <div style="font-size: 0.9rem; color: var(--text-muted); font-weight: 500;">Sorted by Severity</div>
        </div>

        {findings_html}

        <footer>
            <div style="margin-bottom: 16px; font-weight: 700; color: var(--primary); letter-spacing: 0.1em;">🛡️ VEXA</div>
            <div>&copy; {datetime.now().year} Vexa Professional Security Auditing Engine</div>
            <div style="font-size: 0.75rem; margin-top: 8px;">Confidential Report - Internal Use Only</div>
        </footer>
    </div>
</body>
</html>"""

    def _render_findings(
        self, findings: List[Finding], sanitizer: OutputSanitizer
    ) -> str:
        """Render findings as professional cards."""
        if not findings:
            return '<div class="summary-card" style="text-align: center; padding: 40px;"><div class="stat-value" style="color: var(--success); font-size: 3rem;">✅</div><p style="font-weight: 600; margin-top: 10px;">No security issues detected.</p></div>'

        html_parts = []

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                f.severity.value if hasattr(f.severity, "value") else f.severity, 5
            ),
        )

        for i, finding in enumerate(sorted_findings):
            severity = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else finding.severity
            )
            finding_id = f"finding-{i}"

            # Tags for CWE
            tags_html = ""
            if finding.cwe_ids or finding.mitre_attack_id or finding.nist_controls:
                tags = "".join(
                    f'<span class="tag">{sanitizer.escape_html(cwe)}</span>'
                    for cwe in finding.cwe_ids
                )
                mitre = (
                    f'<span class="tag" style="background: #fff7ed; border-color: #fdba74;">{sanitizer.escape_html(finding.mitre_attack_id)}</span>'
                    if finding.mitre_attack_id
                    else ""
                )
                nist = " ".join(
                    f'<span class="tag" style="background: #f0f9ff; border-color: #bae6fd;">{sanitizer.escape_html(nist)}</span>'
                    for nist in finding.nist_controls
                )
                tags_html = f'<div class="tags">{tags}{mitre}{nist}</div>'

            # Code snippet sections
            code_html = ""
            if finding.code_snippet:
                code_html = f"""
                <div class="code-block-container">
                    <div class="code-header">
                        <span>SOURCE CODE</span>
                        <span>{sanitizer.escape_html(finding.file_path)} : {finding.line_start}</span>
                    </div>
                    <pre class="code-snippet"><code>{sanitizer.escape_html(finding.code_snippet)}</code></pre>
                </div>
                """

            html_parts.append(f"""
            <div class="finding-card" id="{finding_id}">
                <div class="finding-header">
                    <div class="finding-info">
                        <span class="finding-title">{sanitizer.escape_html(finding.title)}</span>
                        <div class="finding-meta">
                            <span>📁 {sanitizer.escape_html(finding.file_path)}:{finding.line_start}</span>
                            <span class="scanner-badge">🔍 {sanitizer.escape_html(finding.scanner.upper())}</span>
                        </div>
                    </div>
                    <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 8px;">
                        <span class="severity-badge" style="background: var(--{severity});">{severity}</span>
                        {f'<span class="severity-badge" style="background: #64748b; font-size: 0.6rem; border: 1px solid #e2e8f0; color: #f8fafc;">🚫 FALSE POSITIVE ({finding.false_positive_confidence * 100:.0f}%)</span>' if getattr(finding, "is_false_positive", False) else ""}
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-description">{self._render_markdown(finding.description, sanitizer)}</div>
                    
                    {code_html}
                    
                    {tags_html}

                    <!-- AI Enrichment Section -->
                    {self._render_enhanced_details(finding, sanitizer) if hasattr(finding, "detailed_description") else ""}
                </div>
            </div>
            """)

        return "\n".join(html_parts)

    def _render_toc(self, findings: List[Finding], sanitizer: OutputSanitizer) -> str:
        """Render a compact table of contents for quick navigation."""
        if len(findings) < 5:
            return ""

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                f.severity.value if hasattr(f.severity, "value") else f.severity, 5
            ),
        )

        toc_items = []
        for i, f in enumerate(sorted_findings):
            severity = f.severity.value if hasattr(f.severity, "value") else f.severity
            # Only show critical/high in TOC if many findings
            if severity not in ["critical", "high"] and len(findings) > 20:
                continue

            toc_items.append(f"""
                <a href="#finding-{i}" class="toc-item">
                    <span style="width: 10px; height: 10px; border-radius: 50%; background: var(--{severity}); box-shadow: 0 0 0 2px white, 0 0 0 3px var(--{severity}); flex-shrink: 0;"></span>
                    <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{sanitizer.escape_html(f.title)}</span>
                </a>
            """)

        return f"""
        <div class="toc-container">
            <h3 style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.15em; color: var(--text-muted); margin-bottom: 20px; font-weight: 700;">⚡ Quick Navigation</h3>
            <div class="toc-grid">
                {"".join(toc_items)}
            </div>
        </div>
        """

    def _calculate_health_index(self, counts: Dict[str, int]) -> int:
        """Calculate weighted security health index (0-100)."""
        # Penalties as per TDD-style weighting
        penalties = {"critical": 25, "high": 10, "medium": 3, "low": 1}
        total_penalty = sum(
            counts.get(sev, 0) * penalties.get(sev, 0) for sev in penalties
        )
        score = max(0, 100 - total_penalty)
        return score

    def _get_health_color(self, score: int) -> str:
        """Get color based on health score."""
        if score >= 90:
            return "#10b981"  # Green
        if score >= 70:
            return "#f59e0b"  # Yellow
        if score >= 40:
            return "#f97316"  # Orange
        return "#ef4444"  # Red

    def _get_health_label(self, score: int) -> str:
        """Get rating label based on health score."""
        if score >= 90:
            return "Excellent"
        if score >= 70:
            return "Good"
        if score >= 40:
            return "Fair"
        return "Poor"

    def _render_severity_distribution(self, counts: Dict[str, int], total: int) -> str:
        """Render CSS-based distribution bars."""
        rows = []
        for sev in ["critical", "high", "medium", "low"]:
            count = counts.get(sev, 0)
            percentage = (count / total * 100) if total > 0 else 0

            rows.append(f"""
            <div class="severity-row">
                <div class="severity-name">{sev}</div>
                <div class="progress-bg">
                    <div class="progress-bar" style="width: {percentage}%; background: var(--{sev});"></div>
                </div>
                <div class="count-pill">{count}</div>
            </div>
            """)
        return "\n".join(rows)

    def _render_enhanced_details(
        self, finding: Finding, sanitizer: OutputSanitizer
    ) -> str:
        """Render AI-enhanced details with specialized layout."""
        # Enhancement Grid
        details = ['<div class="enhancement-grid">']

        # Detailed Analysis
        if finding.detailed_description:
            # Check for AI error message
            if "AI Analysis Failed" in finding.detailed_description:
                header_title = "⚠️ Analysis Status"
                content_html = f"<div style=\"color: #9a3412; font-style: italic; background: #fffaf5; padding: 16px; border-radius: 12px; border: 1px solid #ffedd5; font-size: 0.9rem; font-family: 'Inter', sans-serif;\">{sanitizer.escape_html(finding.detailed_description)}</div>"
            else:
                header_title = "📝 Detailed Analysis"
                content_html = self._render_markdown(
                    finding.detailed_description, sanitizer
                )

            details.append(f"""
            <div class="enhancement-box" style="grid-column: span 2;">
                <h4>{header_title}</h4>
                <div class="enhancement-content">{content_html}</div>
            </div>
            """)

        # Threat Analysis Section (Attack & Impact)
        details.append(f"""
            <div class="enhancement-box" style="border-left: 4px solid var(--primary); background: #eff6ff;">
                <h4>⚔️ Attack Scenario</h4>
                <div class="enhancement-content" style="color: #1e40af;">{self._render_markdown(finding.attack_scenario, sanitizer) if finding.attack_scenario else "<i>No attack scenario generated.</i>"}</div>
            </div>
            """)

        details.append(f"""
            <div class="enhancement-box" style="border-left: 4px solid var(--primary); background: #eff6ff;">
                <h4>💼 Business Impact</h4>
                <div class="enhancement-content" style="color: #1e40af;">{self._render_markdown(finding.business_impact, sanitizer) if finding.business_impact else "<i>No business impact analysis generated.</i>"}</div>
            </div>
            """)

        # Remediation Section
        if finding.remediation_code:
            is_error = "# AI Analysis Failed" in finding.remediation_code

            if is_error:
                header_style = "background: #fff7ed; border-bottom: 1px solid #fed7aa;"
                text_style = "color: #c2410c;"
                header_title = "⚠️ REMEDIATION STATUS"
                header_subtitle = "Generation Failed"
                snippet_class = "code-snippet"
                main_header_html = ""
            else:
                header_style = "background: #ecfdf5; border-bottom: 1px solid #bbf7d0;"
                text_style = "color: #065f46;"
                header_title = "SECURE FIX"
                header_subtitle = "Verified by Vexa AI"
                snippet_class = "code-snippet remediation-snippet"
                main_header_html = "<h4>✅ Suggested Remediation</h4>"

            details.append(f"""
            <div class="enhancement-box" style="grid-column: span 2;">
                {main_header_html}
                <div class="code-block-container" style="margin-top: 10px;">
                    <div class="code-header" style="{header_style}">
                        <span style="{text_style}">{header_title}</span>
                        <span style="{text_style}">{header_subtitle}</span>
                    </div>
                    <pre class="{snippet_class}"><code>{sanitizer.escape_html(finding.remediation_code)}</code></pre>
                </div>
            </div>
            """)

        # Implementation Steps & Rollback
        if finding.implementation_steps:
            steps_html = "".join(
                f'<li style="margin-bottom: 8px;">{self._render_markdown(step, sanitizer)}</li>'
                for step in finding.implementation_steps
            )
            details.append(f"""
            <div class="enhancement-box" style="grid-column: span 2;">
                <h4>🛠️ Implementation Steps</h4>
                <div class="enhancement-content">
                    <ol style="padding-left: 18px;">{steps_html}</ol>
                </div>
            </div>
            """)

        # Verification Test Cases
        test_cases = getattr(finding, "test_cases", [])
        if test_cases:
            tests_html = "".join(
                f'<div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px; border-radius: 6px; margin-bottom: 8px; font-size: 0.85rem;"><span style="color: #15803d; font-weight: 700;">TEST</span>: {self._render_markdown(test, sanitizer)}</div>'
                for test in test_cases
            )
            details.append(f"""
            <div class="enhancement-box" style="grid-column: span 2;">
                <h4>🧪 Verification Test Cases</h4>
                <div class="enhancement-content">{tests_html}</div>
            </div>
            """)

        # Cloud Specific Recommendations
        gcp_rec = getattr(finding, "google_cloud_recommendation", "")
        if gcp_rec:
            details.append(f"""
            <div class="enhancement-box" style="border-left: 4px solid #4285f4; background: #f8fafc;">
                <h4><img src="https://www.gstatic.com/images/branding/product/1x/google_64dp.png" height="16" style="vertical-align: middle;"> Google Cloud Recommendation</h4>
                <div class="enhancement-content">{self._render_markdown(gcp_rec, sanitizer)}</div>
            </div>
            """)

        aws_rec = getattr(finding, "aws_recommendation", "")
        if aws_rec:
            pillar = getattr(finding, "aws_well_architected_pillar", "")
            pillar_html = (
                f'<div style="font-size: 0.7rem; color: #c2410c; margin-bottom: 4px;"><strong>Pillar:</strong> {sanitizer.escape_html(pillar)}</div>'
                if pillar
                else ""
            )
            details.append(f"""
            <div class="enhancement-box" style="border-left: 4px solid #ff9900; background: #fffcf5;">
                <h4><img src="https://a0.awsstatic.com/libra-css/images/logos/aws_smile_header_desktop.png" height="12" style="vertical-align: middle;"> AWS Recommendation</h4>
                <div class="enhancement-content">
                    {pillar_html}
                    {self._render_markdown(aws_rec, sanitizer)}
                </div>
            </div>
            """)

        # Documentation Links
        links = getattr(finding, "google_cloud_doc_links", []) or getattr(
            finding, "aws_doc_links", []
        )
        if links:
            links_html = "".join(
                f'<li><a href="{link}" target="_blank" style="color: var(--primary); text-decoration: none;">{sanitizer.escape_html(link)}</a></li>'
                for link in links
            )
            details.append(f"""
            <div class="enhancement-box" style="grid-column: span 2;">
                <h4>📚 Documentation & References</h4>
                <div class="enhancement-content">
                    <ul style="padding-left: 18px; list-style-type: square;">{links_html}</ul>
                </div>
            </div>
            """)

        details.append("</div>")
        return "".join(details)


# Register with ReportGenerator
ReportGenerator.register(HTMLReportGenerator)
