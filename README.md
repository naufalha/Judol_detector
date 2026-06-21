# 🛡️ Judol Detector

Sistem deteksi otomatis link **judi online (judol)** yang terintegrasi dengan **Pi-hole v6** dan **DeepSeek LLM**. Dioptimasi untuk berjalan di **Raspberry Pi** dengan Raspbian.

## Cara Kerja

```
Pi-hole DNS Logs → Collector → Filter (skip analyzed) → DeepSeek LLM → Block di Pi-hole
```

1. **Collect**: Mengambil DNS query dari Pi-hole v6 API
2. **Filter**: Skip domain yang sudah pernah dianalisis (hemat API)
3. **Analyze**: Kirim domain baru ke DeepSeek untuk deteksi judol
4. **Block**: Otomatis tambahkan domain judol ke Pi-hole deny list
5. **Report**: Generate laporan deteksi

## Quick Start

### 1. Clone & Setup

```bash
git clone <repo-url> ~/judol_detector
cd ~/judol_detector
sudo chmod +x setup.sh
sudo ./setup.sh
```

### 2. Konfigurasi

Edit file `.env`:

```bash
nano .env
```

Parameter wajib:
- `PIHOLE_URL` — URL Pi-hole (contoh: `http://192.168.1.1`)
- `PIHOLE_PASSWORD` — Password admin Pi-hole v6
- `DEEPSEEK_API_KEY` — API key dari [DeepSeek Platform](https://platform.deepseek.com/)

### 3. Test

```bash
# Scan sekali (dry-run, tanpa auto-block)
venv/bin/python -m judol_detector scan --dry-run

# Scan sekali (dengan auto-block jika AUTO_BLOCK=true)
venv/bin/python -m judol_detector scan
```

### 4. Jalankan sebagai Service

```bash
sudo systemctl enable judol-detector
sudo systemctl start judol-detector

# Cek status
sudo systemctl status judol-detector

# Lihat log realtime
sudo journalctl -u judol-detector -f
```

## Perintah CLI

| Perintah | Deskripsi |
|---|---|
| `python -m judol_detector scan` | Scan sekali |
| `python -m judol_detector scan --dry-run` | Scan tanpa auto-block |
| `python -m judol_detector daemon` | Jalankan terus-menerus (loop) |
| `python -m judol_detector report` | Generate HTML report |
| `python -m judol_detector stats` | Lihat statistik |
| `python -m judol_detector list` | List domain judol terdeteksi |
| `python -m judol_detector unblock domain.com` | Unblock domain |

## Konfigurasi (.env)

| Variable | Default | Deskripsi |
|---|---|---|
| `PIHOLE_URL` | `http://192.168.1.1` | URL Pi-hole |
| `PIHOLE_PASSWORD` | - | Password admin Pi-hole v6 |
| `DEEPSEEK_API_KEY` | - | API key DeepSeek |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Base URL DeepSeek API |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Model DeepSeek |
| `SCAN_INTERVAL` | `60` | Interval scan dalam detik |
| `BATCH_SIZE` | `100` | Maks domain per batch ke LLM |
| `QUERY_LIMIT` | `1000` | Jumlah query dari Pi-hole per scan |
| `AUTO_BLOCK` | `false` | Auto-block domain judol |
| `LOG_LEVEL` | `INFO` | Level logging |
| `DB_PATH` | `data/judol_history.db` | Path database SQLite |
| `REPORTS_DIR` | `reports` | Directory untuk report HTML |

## Efisiensi

- **Domain tracking**: Setiap domain hanya dianalisis **SEKALI**. Hasil disimpan di SQLite database.
- **Whitelist built-in**: Domain populer (Google, YouTube, Facebook, dll) otomatis di-skip.
- **Batch processing**: Domain dikirim dalam batch ke DeepSeek untuk minimalisir API calls.
- **Fallback rule-based**: Jika DeepSeek API gagal, sistem tetap bisa deteksi menggunakan pattern matching.

## Arsitektur

```
judol_detector/
├── __init__.py      # Package info
├── __main__.py      # Entry point (python -m)
├── main.py          # CLI & orchestrator
├── config.py        # Load konfigurasi dari .env
├── db.py            # SQLite database manager
├── collector.py     # Pi-hole v6 API collector
├── analyzer.py      # DeepSeek LLM analyzer
├── blocker.py       # Pi-hole domain blocker
├── reporter.py      # Report generator
└── utils.py         # Utilities
```

## Optimasi Raspbian

- SQLite dengan WAL mode untuk performa I/O optimal
- Memory limit 256MB via systemd
- CPU quota 50% agar Pi-hole tidak terganggu
- Graceful shutdown handling
- Minimal dependencies

## Troubleshooting

### Pi-hole connection error
```bash
# Pastikan Pi-hole berjalan
sudo systemctl status pihole-FTL

# Test koneksi API
curl -s http://localhost/api/info | python3 -m json.tool
```

### DeepSeek API error
```bash
# Cek API key valid
curl -s https://api.deepseek.com/v1/models \
  -H "Authorization: Bearer YOUR_API_KEY" | python3 -m json.tool
```

### Lihat log detail
```bash
# Log systemd
sudo journalctl -u judol-detector --since "1 hour ago"

# Atau jalankan manual dengan debug
LOG_LEVEL=DEBUG venv/bin/python -m judol_detector scan
```

## License

MIT
