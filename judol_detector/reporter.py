"""Reporter - Menghasilkan laporan deteksi judol.

Output ke console (rich table) dan file HTML.
"""

import os
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def print_scan_report(scan_result, detected_domains: list[dict]):
    """Print laporan scan ke console menggunakan rich."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        console = Console()

        # Header
        console.print()
        console.print(
            Panel(
                f"[bold cyan]Judol Detector[/bold cyan] - Scan Report\n"
                f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
                box=box.DOUBLE,
            )
        )

        # Summary
        summary_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        summary_table.add_column("Key", style="bold")
        summary_table.add_column("Value", style="cyan")
        summary_table.add_row("Total Queries", str(scan_result.get('total_queries', 0)))
        summary_table.add_row("Unique Domains", str(scan_result.get('unique_domains', 0)))
        summary_table.add_row("New Domains", str(scan_result.get('new_domains', 0)))
        summary_table.add_row(
            "Detected Judol",
            f"[bold red]{scan_result.get('detected_judol', 0)}[/bold red]"
            if scan_result.get('detected_judol', 0) > 0
            else "[green]0[/green]"
        )
        summary_table.add_row("Blocked", str(scan_result.get('blocked', 0)))
        console.print(summary_table)

        # Detected domains table
        if detected_domains:
            console.print()
            console.print("[bold red]⚠ Domain Judol Terdeteksi:[/bold red]")
            
            det_table = Table(box=box.ROUNDED)
            det_table.add_column("#", style="dim", width=4)
            det_table.add_column("Domain", style="bold red")
            det_table.add_column("Confidence", justify="center")
            det_table.add_column("Alasan", style="yellow")

            for i, d in enumerate(detected_domains, 1):
                conf = d.get('confidence', 0)
                conf_str = f"{'🔴' if conf >= 0.7 else '🟡'} {conf:.0%}"
                det_table.add_row(
                    str(i),
                    d.get('domain', ''),
                    conf_str,
                    d.get('reason', '')[:60]
                )

            console.print(det_table)
        else:
            console.print("\n[green]✓ Tidak ada domain judol terdeteksi[/green]")

        console.print()

    except ImportError:
        # Fallback tanpa rich
        _print_plain_report(scan_result, detected_domains)


def _print_plain_report(scan_result, detected_domains: list[dict]):
    """Fallback plain text report jika rich tidak tersedia."""
    print("\n" + "=" * 60)
    print("  JUDOL DETECTOR - Scan Report")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"  Total Queries   : {scan_result.get('total_queries', 0)}")
    print(f"  Unique Domains  : {scan_result.get('unique_domains', 0)}")
    print(f"  New Domains     : {scan_result.get('new_domains', 0)}")
    print(f"  Detected Judol  : {scan_result.get('detected_judol', 0)}")
    print(f"  Blocked         : {scan_result.get('blocked', 0)}")
    
    if detected_domains:
        print("\n  ⚠ Domain Judol Terdeteksi:")
        for i, d in enumerate(detected_domains, 1):
            print(f"  {i}. {d.get('domain', '')} "
                  f"(confidence: {d.get('confidence', 0):.0%}) "
                  f"- {d.get('reason', '')}")
    else:
        print("\n  ✓ Tidak ada domain judol terdeteksi")
    
    print("=" * 60 + "\n")


def generate_html_report(db, reports_dir: str) -> str:
    """Generate laporan HTML.
    
    Args:
        db: Database instance
        reports_dir: Directory untuk menyimpan report
        
    Returns:
        Path ke file HTML yang dibuat
    """
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    
    stats = db.get_stats()
    judol_domains = db.get_all_judol_domains()
    recent_scans = db.get_recent_scans(limit=50)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"judol_report_{timestamp}.html"
    filepath = os.path.join(reports_dir, filename)

    html = _build_html(stats, judol_domains, recent_scans)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    
    logger.info(f"HTML report disimpan: {filepath}")
    return filepath


def _build_html(stats: dict, judol_domains: list, recent_scans: list) -> str:
    """Build HTML report string."""
    domain_rows = ""
    for i, d in enumerate(judol_domains, 1):
        conf = d.get('confidence', 0)
        conf_class = 'high' if conf >= 0.7 else 'medium' if conf >= 0.4 else 'low'
        domain_rows += f"""
        <tr>
            <td>{i}</td>
            <td class="domain">{d.get('domain', '')}</td>
            <td class="confidence {conf_class}">{conf:.0%}</td>
            <td>{d.get('reason', '')}</td>
            <td>{d.get('analyzed_at', '')}</td>
        </tr>"""

    scan_rows = ""
    for s in recent_scans:
        scan_rows += f"""
        <tr>
            <td>{s.get('timestamp', '')}</td>
            <td>{s.get('total_queries', 0)}</td>
            <td>{s.get('unique_domains', 0)}</td>
            <td>{s.get('new_domains', 0)}</td>
            <td class="{'detected' if s.get('detected_judol', 0) > 0 else ''}">
                {s.get('detected_judol', 0)}
            </td>
            <td>{s.get('blocked', 0)}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Judol Detector - Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .subtitle {{ color: #94a3b8; margin-bottom: 2rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #3b82f6;
        }}
        .stat-card .label {{ color: #94a3b8; font-size: 0.9rem; }}
        .stat-card.danger .value {{ color: #ef4444; }}
        .stat-card.success .value {{ color: #22c55e; }}
        .section {{ margin-bottom: 2rem; }}
        .section h2 {{
            font-size: 1.3rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #334155;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
            border-radius: 12px;
            overflow: hidden;
        }}
        th {{
            background: #334155;
            padding: 0.8rem 1rem;
            text-align: left;
            font-weight: 600;
            color: #94a3b8;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        td {{
            padding: 0.7rem 1rem;
            border-bottom: 1px solid #1e293b;
        }}
        tr:hover {{ background: #263045; }}
        .domain {{ font-weight: bold; color: #f87171; }}
        .confidence.high {{ color: #ef4444; font-weight: bold; }}
        .confidence.medium {{ color: #f59e0b; }}
        .confidence.low {{ color: #94a3b8; }}
        .detected {{ color: #ef4444; font-weight: bold; }}
        .footer {{
            margin-top: 3rem;
            text-align: center;
            color: #475569;
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Judol Detector Report</h1>
        <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="stats">
            <div class="stat-card">
                <div class="value">{stats.get('total_scans', 0)}</div>
                <div class="label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="value">{stats.get('total_analyzed', 0)}</div>
                <div class="label">Domains Analyzed</div>
            </div>
            <div class="stat-card danger">
                <div class="value">{stats.get('total_judol', 0)}</div>
                <div class="label">Judol Detected</div>
            </div>
            <div class="stat-card success">
                <div class="value">{stats.get('total_safe', 0)}</div>
                <div class="label">Safe Domains</div>
            </div>
            <div class="stat-card danger">
                <div class="value">{stats.get('active_blocks', 0)}</div>
                <div class="label">Active Blocks</div>
            </div>
        </div>

        <div class="section">
            <h2>🚨 Detected Judol Domains ({len(judol_domains)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Domain</th>
                        <th>Confidence</th>
                        <th>Reason</th>
                        <th>Detected At</th>
                    </tr>
                </thead>
                <tbody>
                    {domain_rows if domain_rows else '<tr><td colspan="5" style="text-align:center;color:#22c55e;">Tidak ada domain judol terdeteksi</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>📊 Recent Scan History</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Queries</th>
                        <th>Unique</th>
                        <th>New</th>
                        <th>Judol</th>
                        <th>Blocked</th>
                    </tr>
                </thead>
                <tbody>
                    {scan_rows if scan_rows else '<tr><td colspan="6" style="text-align:center;">Belum ada scan history</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Judol Detector v1.0.0 | Pi-hole + DeepSeek LLM
        </div>
    </div>
</body>
</html>"""


def print_stats(db):
    """Print statistik keseluruhan."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        console = Console()
        stats = db.get_stats()

        table = Table(box=box.ROUNDED, title="Judol Detector Statistics")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right", style="cyan")
        table.add_row("Total Scans", str(stats['total_scans']))
        table.add_row("Domains Analyzed", str(stats['total_analyzed']))
        table.add_row("Judol Detected", f"[red]{stats['total_judol']}[/red]")
        table.add_row("Safe Domains", f"[green]{stats['total_safe']}[/green]")
        table.add_row("Active Blocks", f"[red]{stats['active_blocks']}[/red]")
        console.print(table)

    except ImportError:
        stats = db.get_stats()
        print("\nJudol Detector Statistics:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
