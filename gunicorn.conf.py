import os

max_workers_str = os.getenv("MAX_WORKERS", "2")
use_max_workers = int(max_workers_str)

host = os.getenv("HOST", "0.0.0.0")
port = os.getenv("PORT", "8000")
use_loglevel = os.getenv("LOG_LEVEL", "info")
use_bind = f"{host}:{port}"

accesslog_var = os.getenv("ACCESS_LOG", "-")
use_accesslog = accesslog_var or None
errorlog_var = os.getenv("ERROR_LOG", "-")
use_errorlog = errorlog_var or None
graceful_timeout_str = os.getenv("GRACEFUL_TIMEOUT", "120")
timeout_str = os.getenv("TIMEOUT", "120")
keepalive_str = os.getenv("KEEP_ALIVE", "5")


# Gunicorn config variables
loglevel = use_loglevel
workers = use_max_workers
bind = use_bind
errorlog = use_errorlog
accesslog = use_accesslog
graceful_timeout = int(graceful_timeout_str)
timeout = int(timeout_str)
keepalive = int(keepalive_str)
