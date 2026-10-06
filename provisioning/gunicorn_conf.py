"""Gunicorn configuration for production (loopback only).

Run:  gunicorn app.main:app -c provisioning/gunicorn_conf.py

NOTE: use a SINGLE worker. Scan concurrency comes from the in-process scan
thread pool (CO_MAX_CONCURRENT_RUNS), not from gunicorn workers — and a single
worker keeps the in-memory WebSocket event bus coherent (live progress reaches
the browser reliably). For a multi-worker deployment you would need a shared
pub/sub (e.g. Redis) for cross-worker live events; the UI's poll fallback keeps
results correct either way.
"""
bind = "127.0.0.1:8777"          # loopback only — never expose directly
workers = 1                      # see note above; scale scans via CO_MAX_CONCURRENT_RUNS
worker_class = "uvicorn.workers.UvicornWorker"   # ASGI + WebSocket support
timeout = 1800                   # allow long scans before worker kill
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
proc_name = "cyberorch"
