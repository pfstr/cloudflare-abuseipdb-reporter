# Cloudflare WAF to AbuseIPDB

A GitHub Action that reports IP addresses blocked by selected [Cloudflare WAF](https://developers.cloudflare.com/waf/custom-rules/) custom rules to [AbuseIPDB](https://www.abuseipdb.com/). It runs on a schedule in your own repository. You don't need a server or any dependencies, and it uses a read-only Cloudflare token.

Built and run in production by [Rafael Pfister](https://rafaelpfister.ch/?utm_source=github&utm_medium=readme&utm_campaign=cloudflare-abuseipdb-reporter). Background and walkthrough: [Reporting Cloudflare WAF blocks to AbuseIPDB automatically](https://rafaelpfister.ch/en/blog/cloudflare-waf-abuseipdb?utm_source=github&utm_medium=readme&utm_campaign=cloudflare-abuseipdb-reporter).

## What it does

- Reads the firewall events of the rule IDs you choose from the Cloudflare GraphQL Analytics API (`firewallEventsAdaptive`). This works on the Free plan.
- Groups the events per IP and sends **one report per IP** with the method and path of the blocked requests, timestamped at the first event.
- Keeps track of the last reported hour in the Actions cache. A late or skipped scheduled run is caught up on the next run, and no hour is reported twice.
- Skips private, loopback, link-local, CGNAT and ULA addresses, plus any IPs you list.
- Writes a summary table (IP, ASN, country, events, AbuseIPDB score) to the job summary.

## Why only selected rules

Report what is unambiguous. A rule that blocks `/wp-login.php` on a site without WordPress, or `/.env` on any site, only matches scanners. Rate limits, bot scores, geo blocks and managed challenges also hit search engine crawlers and real visitors, and reporting them pollutes the database. That is why `rule-ids` is required and there is no "report everything" mode.

## Setup

### 1. A WAF rule worth reporting

Create a custom rule (Security, WAF, Custom rules) with the action **Block** for paths your site never serves. An example for sites without PHP or WordPress is in [`examples/waf-rule-static-site.txt`](examples/waf-rule-static-site.txt). Before you activate it, check it against your own URLs (for example, all URLs in your sitemap).

For more building blocks, see [sefinek/Cloudflare-WAF-Expressions](https://github.com/sefinek/Cloudflare-WAF-Expressions), a maintained collection of WAF expressions for suspicious paths, file extensions, injections and bots. Pick the path and extension parts for the rule you report. Parts that match user agents, referrers or bot categories also hit legitimate clients (API tools, AI agents, crawlers); keep those in a separate rule that you don't report.

### 2. Rule ID

Open Security, Events, expand a blocked request of that rule and copy the 32-character ID under **Rule**. If you edit the rule later, the ID stays the same. A rule you delete and recreate gets a new ID.

### 3. Cloudflare API token

My Profile, API Tokens, Create Token, Custom token, with a single permission:

| Permission | Access |
|---|---|
| Zone, Analytics | Read |

Limit it to the zone. Store it as the repository secret `CF_ANALYTICS_TOKEN`.

### 4. AbuseIPDB API key

Create an account at [abuseipdb.com](https://www.abuseipdb.com/), then Account, API, Create Key. Store it as `ABUSEIPDB_API_KEY`. I recommend verifying your domain under Account, Webmasters: verified webmasters get more weight on their reports and a higher daily quota.

### 5. Workflow

Copy [`examples/abuseipdb-report.yml`](examples/abuseipdb-report.yml) to `.github/workflows/` in a private repository, fill in `zone-id` and `rule-ids`, and run it once manually with `dry-run` to see what would be reported.

```yaml
- uses: pfstr/cloudflare-abuseipdb-reporter@v1
  with:
    cloudflare-api-token: ${{ secrets.CF_ANALYTICS_TOKEN }}
    abuseipdb-api-key: ${{ secrets.ABUSEIPDB_API_KEY }}
    zone-id: <zone id>
    rule-ids: <rule id>
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `cloudflare-api-token` | (required) | Token with Zone, Analytics, Read |
| `abuseipdb-api-key` | | Not needed for `dry-run` and `csv-file` |
| `zone-id` | (required) | Cloudflare zone ID |
| `rule-ids` | (required) | Comma-separated WAF rule IDs |
| `waf-actions` | `block` | Comma-separated WAF actions to include |
| `categories` | `21` | [AbuseIPDB categories](https://www.abuseipdb.com/categories), 21 = Web App Attack |
| `comment` | `Blocked by Cloudflare WAF: {count} request(s): {requests}` | Report text, placeholders `{count}` and `{requests}`. Comments are capped at 1000 characters; a long request list is shortened so text after it is kept |
| `credit` | `true` | Appends ` • Reported by: github.com/pfstr/cloudflare-abuseipdb-reporter` to each comment; `false` turns it off |
| `min-hits` | `1` | Minimum events per IP in the window |
| `ignore-ips` | | Comma-separated IPs never to report |
| `hours` | | Empty = catch up since the last run; number = fixed window, state unchanged |
| `end-offset-hours` | `0` | Shift the end of a fixed window back (backfill) |
| `max-lookback-hours` | `72` | Upper limit for catching up |
| `dry-run` | `false` | List only |
| `csv-file` | | Write a CSV for [bulk-report](https://www.abuseipdb.com/bulk-report) instead of reporting |
| `state-key` | `abuseipdb-state-` | Cache key prefix; use different values for several zones in one repository |

## Reporting window and state

Each run reports `[last reported hour, last full hour)` in UTC, and stores the end in the Actions cache. Only a run without errors advances the state, so a failed window is retried. GitHub does not guarantee scheduled runs and sometimes skips them for hours. The state makes that harmless, up to `max-lookback-hours`. Cloudflare's own retention for firewall events also depends on the plan.

AbuseIPDB accepts one report per IP and account every 15 minutes. If an IP shows up again within that time (for example in a manual backfill), the action logs it as `skipped (429)` and does not count it as an error.

## Privacy

AbuseIPDB reports are public. The action sends only the IP address, the timestamp, the categories and your comment. The default comment contains method and path, no host, user agent, headers or query strings. Keep it that way when you write your own template. Reporting attacking IP addresses to a threat-intelligence service is a common security measure, but check it against the data protection law that applies to you (e.g. revDSG in Switzerland, GDPR in the EU).

## Quotas

- AbuseIPDB free account: 1,000 reports per day; more for verified webmasters and paid plans.
- Cloudflare GraphQL: up to 10,000 events per request; the action pages through larger windows.
- GitHub Actions: an hourly job takes well under a minute. In a private repository that is roughly 750 of the 2,000 free minutes per month (each run is rounded up to one minute).

## Self-hosted runners

The action needs Node.js 20 or newer on the runner (`ubuntu-latest` has it). It has no npm dependencies.

## License

MIT, see [LICENSE](LICENSE). Not affiliated with Cloudflare or AbuseIPDB.
