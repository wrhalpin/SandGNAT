# How to run the intake service under gunicorn

`sandgnat-intake` (the console script from `pyproject.toml`) launches
Flask's dev server. That's fine for `STATIC_ANALYSIS_ENABLED=0` dev
stacks but nothing you'd expose to the analysis bridge or the GNAT
connector. For anything real, front it with gunicorn.

## Why not the dev server

Flask's `app.run()` is single-threaded, doesn't handle slow clients,
doesn't rotate workers, and logs exceptions in a format no production
log processor understands. gunicorn fixes all of that.

## Install gunicorn

```bash
pip install 'gunicorn>=21.0'
```

(Don't add it to `pyproject.toml` — keeping the package deps minimal
matters for guest freezes. gunicorn is an operator-level dep.)

## Invoke it

```bash
gunicorn \
    --workers 4 \
    --worker-class sync \
    --timeout 120 \
    --bind 0.0.0.0:8080 \
    --access-logfile - \
    --error-logfile - \
    'orchestrator.intake_server:wsgi_app()'
```

`wsgi_app()` returns the Flask app via `create_app()`, reading all
settings from env vars. Workers share nothing; they each spin up
their own psycopg connection pool on first request.

## systemd unit

`/etc/systemd/system/sandgnat-intake.service`:

```ini
[Unit]
Description=SandGNAT intake + export HTTP API
After=network-online.target postgresql.service redis.service
Wants=network-online.target

[Service]
Type=simple
User=sandgnat
Group=sandgnat
EnvironmentFile=/etc/sandgnat/env
WorkingDirectory=/opt/sandgnat
ExecStart=/opt/sandgnat/venv/bin/gunicorn \
    --workers 4 \
    --worker-class sync \
    --timeout 120 \
    --bind 127.0.0.1:8080 \
    --access-logfile - \
    --error-logfile - \
    'orchestrator.intake_server:wsgi_app()'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
systemctl daemon-reload
systemctl enable --now sandgnat-intake
journalctl -u sandgnat-intake -f
```

## Worker count

Rule of thumb: `2 * CPU_cores + 1` for sync workers. For SandGNAT
specifically, the bottleneck is more often Postgres than CPU — 4–8
workers is usually plenty for a single-node deployment. Scale the
worker count separately from the Celery worker count
(`sandgnat-worker`); they're unrelated pools.

## Timeouts

- `--timeout 120` — kills a worker that takes >120 s on any one
  request. `POST /submit` with a 128 MiB file + YARA scan can run
  long; leave headroom.
- If you see `WORKER TIMEOUT` in the logs, bump the timeout or shrink
  `INTAKE_MAX_SAMPLE_BYTES`.

## TLS termination

Gunicorn can serve TLS directly (`--certfile`, `--keyfile`) but the
ergonomics are better if you front with nginx or Caddy:

```nginx
# /etc/nginx/sites-available/sandgnat
upstream sandgnat {
    server 127.0.0.1:8080 fail_timeout=0;
}

server {
    listen 443 ssl http2;
    server_name sandgnat.internal;
    ssl_certificate     /etc/letsencrypt/live/sandgnat.internal/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sandgnat.internal/privkey.pem;

    # Large POST bodies — /submit accepts up to 128 MiB by default.
    client_max_body_size 256m;

    location / {
        proxy_pass http://sandgnat;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 150s;
    }
}
```

Then bind gunicorn to `127.0.0.1:8080` and let nginx handle TLS,
request-size enforcement, and any rate limiting.

## Logging

gunicorn's access log format by default is an NCSA-style single line
per request — good for basic analytics, useless for correlating with
SandGNAT's structured `analysis_audit_log`. Production deployments
ship the gunicorn logs to the same place as the Celery worker logs
and grep by `analysis_id` when debugging.

If you want structured access logs:

```bash
--access-logformat '%(h)s "%(r)s" %(s)s %(b)s %({X-API-Key}i)s %(D)sus'
```

## Health checks

`/healthz` is always on, unauthenticated, and doesn't touch the DB.
Point your load balancer / systemd health check at it.

For a deeper check (does Postgres work?), don't overload `/healthz` —
write a separate `/readyz` yourself if you need it; the current code
base deliberately keeps health dead-simple because a flaky DB
shouldn't take the intake HTTP pod out of rotation when all we care
about is "can the process accept requests?".

## Zero-downtime restart

gunicorn handles `SIGHUP` by rolling workers:

```bash
systemctl reload sandgnat-intake   # or: kill -HUP <master_pid>
```

Workers serving in-flight requests finish; new requests go to fresh
workers. Good for config changes, rule reloads, code pushes that
don't involve DB migrations.

## Non-gunicorn alternatives

- **uwsgi** — works fine, same shape. Pick whichever your ops team
  knows better.
- **hypercorn** — async, but the app is sync Flask, so it'd sit on
  top of asgiref. No benefit.
- **docker + any of the above** — recommended for deployments you
  don't own. The Dockerfile isn't in this repo right now; one-liner:

  ```dockerfile
  FROM python:3.11-slim
  WORKDIR /app
  COPY . .
  RUN pip install -e . gunicorn
  CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "orchestrator.intake_server:wsgi_app()"]
  ```

## Related

- [run a Celery worker for the analysis queue](tune-vm-pools.md)
  — the other half of a real deployment.
