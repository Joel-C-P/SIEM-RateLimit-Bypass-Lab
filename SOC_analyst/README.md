## Context

Before looking for events, I made some login requests using other IPs. 172.16.0.115 will be from RRHH and 172.16.0.130 will be from the admin. So we have to assume that the hacker can't change their IP, well, they can, but we use a Caddy proxy to deny the param "X-Forwarded-For" so that only the real IP is received. So I made this to filter and differentiate between false positives.

172.16.0.115 -> user: RRHH
172.16.0.130 -> user: admin
172.28.0.1 ---> user: Pentester



