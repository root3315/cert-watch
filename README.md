# cert-watch

SSL certificate expiration monitor. Because nobody wants to wake up at 3am to an expired cert alert.

## What it does

Checks SSL certificates for your domains and tells you:
- How many days until expiration
- If you're in the danger zone (warning/critical thresholds)
- Certificate details like issuer, validity dates, serial number

## Quick start

```bash
# Check a single domain
python cert_watch.py example.com

# Check multiple domains
python cert_watch.py example.com google.com github.com

# Verbose output with full certificate details
python cert_watch.py -v example.com

# JSON output for scripting
python cert_watch.py --json example.com
```

## Config file mode

Set up a config file so you don't have to type all your domains every time:

```bash
# Add domains to your config
python cert_watch.py --add example.com
python cert_watch.py --add api.example.com
python cert_watch.py --add shop.example.com

# List what you've configured
python cert_watch.py --list

# Watch all configured domains
python cert_watch.py --watch
```

Config lives at `~/.cert-watch.json` by default. You can change it with `-c`.

## Thresholds

Default warning levels:
- **Warning**: 30 days until expiry
- **Critical**: 7 days until expiry

Override them:

```bash
python cert_watch.py -w 14 -e 3 example.com
```

That warns you at 2 weeks and goes critical at 3 days.

## Exit codes

- `0` - All certificates are healthy
- `1` - At least one cert is expired, critical, or had an error

Useful for CI/CD pipelines or cron jobs.

## Example output

```
================================================================================
CERTIFICATE STATUS SUMMARY
================================================================================
Domain                                   Status          Expires In          
--------------------------------------------------------------------------------
example.com                              OK              89 days             
google.com                               OK              52 days             
expired-site.com                         EXPIRED         15 days ago         
critical-site.com                        CRITICAL        4 days              
--------------------------------------------------------------------------------
Summary: OK=2, Warning=0, Critical=1, Expired=1, Errors=0
================================================================================
```

## Config file format

If you want to edit it manually:

```json
{
  "domains": [
    "example.com",
    "api.example.com",
    "shop.example.com"
  ],
  "warning_days": 30,
  "critical_days": 7
}
```

## Cron job setup

Add to your crontab for daily checks:

```
0 9 * * * /path/to/cert_watch.py --watch >> /var/log/cert-watch.log 2>&1
```

Or with alerting when something's wrong:

```
0 9 * * * /path/to/cert_watch.py --watch || mail -s "Cert Alert" you@example.com
```

## Requirements

- Python 3.6+
- No external dependencies (uses only stdlib: ssl, socket, datetime, json)

## Why I built this

Got burned by an expired certificate on a side project. Lost a weekend debugging why things stopped working. Now I run this daily and sleep better.

## License

Do whatever you want with it.
