# Panel Infrastructure

Deploys an authentication panel based on **Authelia** behind **Caddy**
with internal TLS.

## Services

- **Authelia** — IdP with attempt regulation (rate limiting).
- **Caddy** — Reverse proxy with internal TLS for `authelia.test`.

## Regulation configuration

```yaml
regulation:
  max_retries: 3
  find_time: 60
  ban_time: 60
