## Setup

- I'll use free splunk Version 10.4.3 
- Take logs from /SIEM-RateLimit-Bypass-Lab/Panel_Infrastructure/authelia/authelia.logs
- So import to import this data in _json format in "Set Source Type"

## Notes
    
We got the first "problem" to fix, as i'm using free splunk Version, doesn't let to create my own personalite index name . 
It's so import to be organizated, so inted of use Index main i'll create my own  

## Index creation

Splunk Free does not allow creating custom indexes from the web UI. Use the CLI, so i'll create a index with this command line:

```bash
sudo /opt/splunk/bin/splunk add index management_panel \
  -maxTotalDataSizeMB 500 \
  -frozenTimePeriodInSecs 604800
```
we got two params, the firts mean 500MB of storage limit, in the last params it means that its gonna be recollection data for only 7 days





