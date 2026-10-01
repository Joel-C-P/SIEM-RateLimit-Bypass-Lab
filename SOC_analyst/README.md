## Context

Before looking for events, I made some login requests using other IPs. 172.16.0.115 will be from RRHH and 172.16.0.130 will be from the admin. So we have to assume that the hacker can't change their IP, well, they can, but we use a Caddy proxy to deny the param "X-Forwarded-For" so that only the real IP is received. So I made this to filter and differentiate between false positives.

172.16.0.115 -> user: RRHH
172.16.0.130 -> user: admin
172.28.0.1 ---> user: Pentester

## Objectives

My objective is to detect and analyze suspicious authentication activity, and to document a reproducible response with evidence.

So as I said before, we need to be organized, so I will start by looking at the telemetry that we get.

![Telemetry](Screenshots/splunk_telemetry.png)

Then I will apply a regex and change some variable names using Splunk SPL to make this clearer.

```spl
index="management_panel" host=authelia | spath input=_raw path=remote_ip output=lab_ip | spath input=_raw path=time output=lab_time | spath input=_raw path=msg output=lab_msg | regex lab_msg="^(Unsuccessful|Successful) 1FA authentication attempt" | rex field=lab_msg "by user '(?<lab_user>[^']+)'" | eval lab_action=case(match(lab_msg, "^Unsuccessful"), "failure", match(lab_msg, "^Successful"), "success") | sort 0 lab_time| table lab_time lab_ip lab_user lab_action
```


![Organizated data](Screenshots/spl_filter.png)


## Notes:

I had problems with the interpreter time, it was desynchronized by seconds between Splunk and Authelia time logs. The solution was changing the time parameters of Splunk and restarting it.


