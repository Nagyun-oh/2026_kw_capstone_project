# Targets

This directory contains optional web applications that can run behind the WAF.

The WAF should stay portable: keep target-specific services here and override the
WAF backend only when a target is selected.

## Juice Shop

Run from the repository root:

```bash
docker compose -f waf/docker-compose.yml -f targets/juiceshop/docker-compose.yml up -d
```

Open:

```text
http://localhost
```

The request path is:

```text
Browser -> WAF -> Juice Shop
```

