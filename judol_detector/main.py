"""Main - Entry point dan orchestrator Judol Detector.

Usage:
    python -m judol_detector scan        # Jalankan scan sekali
    python -m judol_detector daemon      # Jalankan sebagai daemon (loop)
    python -m judol_detector report      # Generate HTML report
    python -m judol_detector stats       # Tampilkan statistik
    python -m judol_detector unblock     # Unblock domain
    python -m judol_detector list        # List domain judol terdeteksi
"""

import argparse
import logging
import signal
import sys
import time
from datetime import datetime

from .config import Config
from .db import Database
from .collector import PiholeCollector
from .analyzer import analyze_domains
from .blocker import PiholeBlocker
from .reporter import print_scan_report, generate_html_report, print_stats
from .utils import setup_logging

logger = logging.getLogger(__name__)

# Flag untuk graceful shutdown
_running = True


def _signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM untuk graceful shutdown."""
    global _running
    logger.info("Menerima signal shutdown, menghentikan daemon...")
    _running = False


def run_scan(db: Database, dry_run: bool = False) -> dict:
    """Jalankan satu siklus scan.
    
    Flow:
    1. Collect DNS queries dari Pi-hole
    2. Filter domain yang sudah dianalisis (efisiensi)
    3. Kirim domain baru ke DeepSeek untuk analisis
    4. Simpan hasil ke database
    5. Block domain judol (jika auto_block aktif)
    6. Print report
    
    Returns:
        Dict dengan hasil scan
    """
    result = {
        "total_queries": 0,
        "unique_domains": 0,
        "new_domains": 0,
        "detected_judol": 0,
        "blocked": 0,
    }

    # Step 1: Collect dari Pi-hole
    logger.info("[1/5] Mengumpulkan DNS queries dari Pi-hole...")
    collector = PiholeCollector(
        base_url=Config.PIHOLE_URL,
        password=Config.PIHOLE_PASSWORD
    )
    
    try:
        all_domains = collector.collect(limit=Config.QUERY_LIMIT)
    finally:
        collector.close()

    if not all_domains:
        logger.info("Tidak ada domain untuk diproses")
        return result

    result["total_queries"] = Config.QUERY_LIMIT  # approximate
    
    # Filter whitelist
    domains_filtered = [
        d for d in all_domains if not Config.is_whitelisted(d)
    ]
    result["unique_domains"] = len(domains_filtered)
    logger.info(f"Setelah whitelist filter: {len(domains_filtered)} domain")

    # Step 2: Filter domain yang sudah dianalisis
    logger.info("[2/5] Memfilter domain yang sudah pernah dianalisis...")
    new_domains = db.get_unanalyzed_domains(domains_filtered)
    result["new_domains"] = len(new_domains)
    
    if not new_domains:
        logger.info("Semua domain sudah pernah dianalisis, skip.")
        # Simpan scan result
        db.save_scan_result(**result)
        print_scan_report(result, [])
        return result

    logger.info(f"Ditemukan {len(new_domains)} domain baru untuk dianalisis")

    # Step 3: Analisis dengan DeepSeek
    logger.info("[3/5] Menganalisis domain dengan DeepSeek...")
    analysis_results = analyze_domains(
        api_key=Config.DEEPSEEK_API_KEY,
        base_url=Config.DEEPSEEK_BASE_URL,
        model=Config.DEEPSEEK_MODEL,
        domains=new_domains,
        batch_size=Config.BATCH_SIZE
    )

    # Step 4: Simpan hasil analisis ke database
    logger.info("[4/5] Menyimpan hasil analisis...")
    db.save_analyzed_domains(analysis_results)

    # Filter yang terdeteksi judol
    detected = [r for r in analysis_results if r.get("is_judol")]
    result["detected_judol"] = len(detected)

    # Step 5: Block domain (jika auto_block aktif dan bukan dry_run)
    blocked_count = 0
    if detected and Config.AUTO_BLOCK and not dry_run:
        logger.info("[5/5] Memblokir domain judol di Pi-hole...")
        blocker = PiholeBlocker(
            base_url=Config.PIHOLE_URL,
            password=Config.PIHOLE_PASSWORD
        )
        try:
            for d in detected:
                domain = d["domain"]
                if not db.is_domain_blocked(domain):
                    if blocker.block_domain(
                        domain,
                        comment=f"Judol Detector: {d.get('reason', '')[:100]}"
                    ):
                        db.save_blocked_domain(domain)
                        blocked_count += 1
        finally:
            blocker.close()
    elif detected and not Config.AUTO_BLOCK:
        logger.info("[5/5] Auto-block NONAKTIF. Domain terdeteksi tapi tidak diblokir.")
    else:
        logger.info("[5/5] Tidak ada domain untuk diblokir.")

    result["blocked"] = blocked_count

    # Simpan scan result
    db.save_scan_result(**result)

    # Print report
    print_scan_report(result, detected)

    return result


def run_daemon(db: Database):
    """Jalankan scan dalam loop (daemon mode)."""
    global _running
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    interval = Config.SCAN_INTERVAL
    logger.info(f"Judol Detector daemon dimulai (interval: {interval} detik)")
    logger.info(f"Auto-block: {'AKTIF' if Config.AUTO_BLOCK else 'NONAKTIF'}")
    logger.info("Tekan Ctrl+C untuk menghentikan")

    scan_count = 0
    while _running:
        scan_count += 1
        logger.info(f"\n{'='*50}")
        logger.info(f"Scan #{scan_count} dimulai - {datetime.now().strftime('%H:%M:%S')}")
        logger.info(f"{'='*50}")
        
        try:
            run_scan(db)
        except Exception as e:
            logger.error(f"Error saat scan: {e}", exc_info=True)

        if _running:
            logger.info(f"Scan berikutnya dalam {interval} detik...")
            # Sleep dalam interval kecil untuk responsive shutdown
            for _ in range(interval):
                if not _running:
                    break
                time.sleep(1)

    logger.info("Daemon dihentikan.")


def cmd_unblock(db: Database, domains: list[str]):
    """Unblock domain dari Pi-hole."""
    blocker = PiholeBlocker(
        base_url=Config.PIHOLE_URL,
        password=Config.PIHOLE_PASSWORD
    )
    try:
        for domain in domains:
            if blocker.unblock_domain(domain):
                db.save_unblocked_domain(domain)
                print(f"  ✓ Unblocked: {domain}")
            else:
                print(f"  ✗ Gagal unblock: {domain}")
    finally:
        blocker.close()


def cmd_list_judol(db: Database):
    """List semua domain judol yang terdeteksi."""
    domains = db.get_all_judol_domains()
    if not domains:
        print("Belum ada domain judol yang terdeteksi.")
        return
    
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box

        console = Console()
        table = Table(box=box.ROUNDED, title=f"Domain Judol Terdeteksi ({len(domains)})")
        table.add_column("#", style="dim", width=4)
        table.add_column("Domain", style="bold red")
        table.add_column("Confidence", justify="center")
        table.add_column("Reason")
        table.add_column("Detected At", style="dim")

        for i, d in enumerate(domains, 1):
            conf = d.get('confidence', 0)
            table.add_row(
                str(i),
                d['domain'],
                f"{conf:.0%}",
                d.get('reason', '')[:50],
                d.get('analyzed_at', '')
            )
        console.print(table)
    except ImportError:
        for i, d in enumerate(domains, 1):
            print(f"{i}. {d['domain']} (confidence: {d.get('confidence', 0):.0%})")


def main():
    """Entry point CLI."""
    parser = argparse.ArgumentParser(
        description="Judol Detector - Sistem Deteksi Link Judi Online",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python -m judol_detector scan          # Scan sekali
  python -m judol_detector scan --dry-run # Scan tanpa auto-block
  python -m judol_detector daemon         # Jalankan terus-menerus
  python -m judol_detector report         # Generate HTML report
  python -m judol_detector stats          # Lihat statistik
  python -m judol_detector list           # List domain judol
  python -m judol_detector unblock domain1.com domain2.com
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Perintah")
    
    # scan
    scan_parser = subparsers.add_parser("scan", help="Jalankan scan sekali")
    scan_parser.add_argument("--dry-run", action="store_true",
                             help="Scan tanpa auto-block")
    
    # daemon
    subparsers.add_parser("daemon", help="Jalankan sebagai daemon (loop)")
    
    # report
    subparsers.add_parser("report", help="Generate HTML report")
    
    # stats
    subparsers.add_parser("stats", help="Tampilkan statistik")
    
    # list
    subparsers.add_parser("list", help="List domain judol terdeteksi")
    
    # unblock
    unblock_parser = subparsers.add_parser("unblock", help="Unblock domain")
    unblock_parser.add_argument("domains", nargs="+", help="Domain untuk di-unblock")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Validasi config
    errors = Config.validate()
    if errors and args.command not in ("stats", "list", "report"):
        print("\n❌ Konfigurasi error:")
        for err in errors:
            print(f"  - {err}")
        print("\nPeriksa file .env Anda.")
        sys.exit(1)

    # Setup logging
    setup_logging(level=Config.LOG_LEVEL)
    
    # Init database
    db = Database(Config.DB_PATH)

    # Execute command
    if args.command == "scan":
        run_scan(db, dry_run=args.dry_run)
    
    elif args.command == "daemon":
        run_daemon(db)
    
    elif args.command == "report":
        filepath = generate_html_report(db, Config.REPORTS_DIR)
        print(f"✓ Report disimpan: {filepath}")
    
    elif args.command == "stats":
        print_stats(db)
    
    elif args.command == "list":
        cmd_list_judol(db)
    
    elif args.command == "unblock":
        cmd_unblock(db, args.domains)


if __name__ == "__main__":
    main()
