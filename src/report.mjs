// Reads Cloudflare WAF events of the configured rule(s) and reports the client IPs to AbuseIPDB.
// Configured through environment variables, which action.yml sets from its inputs (see README).

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { aggregate, buildComment, computeWindow, isPrivate, toCsv, withCredit } from "./lib.mjs";

const env = (k, d = "") => (process.env[k] ?? "").trim() || d;
const list = (k, d = "") => env(k, d).split(",").map((s) => s.trim()).filter(Boolean);

const CF_TOKEN = env("CF_API_TOKEN");
const ABUSE_KEY = env("ABUSEIPDB_API_KEY");
const ZONE_ID = env("ZONE_ID");
const RULE_IDS = list("RULE_IDS");
const ACTIONS = list("WAF_ACTIONS", "block");
const CATEGORIES = env("CATEGORIES", "21");
const TEMPLATE = withCredit(
  env("COMMENT", "Blocked by Cloudflare WAF: {count} request(s): {requests}"),
  !["false", "0"].includes(env("CREDIT")),
);
const MIN_HITS = parseInt(env("MIN_HITS", "1"), 10);
const IGNORE = new Set(list("IGNORE_IPS"));
const STATE_FILE = env("STATE_FILE");
const CSV_FILE = env("CSV_FILE");
const DRY_RUN = ["true", "1"].includes(env("DRY_RUN")) || Boolean(CSV_FILE);
const HOURS = env("HOURS") ? parseInt(env("HOURS"), 10) : null;

if (!CF_TOKEN) throw new Error("cloudflare-api-token is required");
if (!ZONE_ID) throw new Error("zone-id is required");
if (!RULE_IDS.length) throw new Error("rule-ids is required");
if (!DRY_RUN && !ABUSE_KEY) throw new Error("abuseipdb-api-key is required (or set dry-run)");

let stateEnd = null;
if (STATE_FILE && existsSync(STATE_FILE)) stateEnd = JSON.parse(readFileSync(STATE_FILE, "utf8")).end;
const win = computeWindow({
  stateEnd,
  hours: HOURS,
  endOffsetHours: parseInt(env("END_OFFSET_HOURS", "0"), 10),
  maxLookbackHours: parseInt(env("MAX_LOOKBACK_HOURS", "72"), 10),
});
if (win.empty) {
  console.log(`Nothing to do: already reported up to ${win.end.toISOString()}`);
  process.exit(0);
}

const QUERY = `query($zone: String!, $start: Time!, $end: Time!, $rules: [String!], $actions: [String!]) {
  viewer { zones(filter: { zoneTag: $zone }) {
    firewallEventsAdaptive(limit: 10000, orderBy: [datetime_ASC],
      filter: { datetime_geq: $start, datetime_lt: $end, ruleId_in: $rules, action_in: $actions }) {
      datetime clientIP clientRequestPath clientRequestHTTPMethodName clientAsn clientCountryName
    }
  } }
}`;

async function fetchEvents() {
  const all = [];
  let from = win.start.toISOString();
  for (;;) {
    const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST",
      headers: { Authorization: `Bearer ${CF_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        query: QUERY,
        variables: { zone: ZONE_ID, start: from, end: win.end.toISOString(), rules: RULE_IDS, actions: ACTIONS },
      }),
    });
    const json = await res.json();
    if (!res.ok || json.errors?.length) {
      throw new Error(`Cloudflare GraphQL ${res.status}: ${JSON.stringify(json.errors)}`);
    }
    const page = json.data.viewer.zones[0]?.firewallEventsAdaptive ?? [];
    all.push(...page);
    if (page.length < 10000) return all;
    // Continue from the last timestamp; repeated same-second events are absorbed by the per-IP aggregation.
    from = page.at(-1).datetime;
  }
}

async function report(ip, comment, timestamp) {
  const res = await fetch("https://api.abuseipdb.com/api/v2/report", {
    method: "POST",
    headers: { Key: ABUSE_KEY, Accept: "application/json" },
    body: new URLSearchParams({ ip, categories: CATEGORIES, comment, timestamp }),
  });
  const json = await res.json().catch(() => ({}));
  if (res.ok) return { status: "reported", score: json.data?.abuseConfidenceScore };
  const detail = json.errors?.[0]?.detail || res.statusText;
  // 429: same IP already reported by this account within 15 minutes, or daily quota reached
  // 422: invalid or protected IP
  if (res.status === 429 || res.status === 422) return { status: `skipped (${res.status})`, detail };
  throw new Error(`AbuseIPDB ${res.status} for ${ip}: ${detail}`);
}

const events = await fetchEvents();
const byIp = aggregate(events);
const mode = DRY_RUN ? " (dry run)" : "";
console.log(`Window ${win.start.toISOString()} to ${win.end.toISOString()}: ${events.length} events, ${byIp.size} IPs${mode}`);

const rows = [];
const summary = [];
let failures = 0;
for (const [ip, e] of byIp) {
  const comment = buildComment(TEMPLATE, e);
  let r;
  if (IGNORE.has(ip) || isPrivate(ip)) r = { status: "ignored" };
  else if (e.count < MIN_HITS) r = { status: `below min-hits (${MIN_HITS})` };
  else if (DRY_RUN) {
    r = { status: "dry run" };
    rows.push({ ip, date: e.first, comment });
  } else {
    try {
      r = await report(ip, comment, e.first);
    } catch (err) {
      failures++;
      r = { status: "error", detail: err.message };
    }
  }
  const score = r.score != null ? `, score ${r.score}` : "";
  console.log(`${ip} AS${e.asn} ${e.country} ${e.count}x -> ${r.status}${score}${r.detail ? ` ${r.detail}` : ""}`);
  summary.push(`| ${ip} | AS${e.asn} | ${e.country} | ${e.count} | ${r.status}${score} |`);
}

if (CSV_FILE) {
  writeFileSync(CSV_FILE, toCsv(rows, CATEGORIES));
  console.log(`${rows.length} IPs written to ${CSV_FILE}`);
}

if (process.env.GITHUB_STEP_SUMMARY) {
  const head = `### AbuseIPDB reports\n\nWindow ${win.start.toISOString()} to ${win.end.toISOString()}: ` +
    `${events.length} events, ${byIp.size} IPs${mode}\n\n`;
  const table = summary.length
    ? `| IP | ASN | Country | Events | Result |\n|---|---|---|---|---|\n${summary.join("\n")}\n`
    : "No events.\n";
  const credit = "\n<sub>[cloudflare-abuseipdb-reporter](https://github.com/pfstr/cloudflare-abuseipdb-reporter) " +
    "by [Rafael Pfister](https://rafaelpfister.ch/?utm_source=github&utm_medium=action-summary&utm_campaign=cloudflare-abuseipdb-reporter)</sub>\n";
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, head + table + credit);
}

// Advance the state only after a complete real run, so a failed window is retried next time.
if (win.useState && STATE_FILE && !DRY_RUN && !failures) {
  writeFileSync(STATE_FILE, JSON.stringify({ end: win.end.toISOString() }) + "\n");
}

if (failures) {
  console.error(`${failures} report(s) failed`);
  process.exit(1);
}
