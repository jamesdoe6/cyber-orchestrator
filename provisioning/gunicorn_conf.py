"""Gunicorn configuration for production (loopback only).

Run:  gunicorn app.main:app -c provisioning/gunicorn_conf.py
"""
bind = "127.0.0.1:8777"          # loopback only — never expose directly
workers = 2                      # scans run synchronously and block a worker;
                                 # 2+ keeps the UI responsive during a long scan
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 1800                   # allow long scans (30 min) before worker kill
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
proc_name = "cyberorch"
