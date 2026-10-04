// Pure helpers, covered by test/lib.test.mjs.

const HOUR = 3600_000;

/**
 * Reporting window [start, end) in whole UTC hours.
 * - hours set: fixed window of `hours` ending `endOffsetHours` before the last full hour, state untouched
 * - otherwise: from the stored state end (first run: 1 hour) up to the last full hour,
 *   never further back than `maxLookbackHours`
 */
export function computeWindow({ now = new Date(), stateEnd = null, hours = null, endOffsetHours = 0, maxLookbackHours = 72 }) {
  const end = new Date(now);
  end.setUTCMinutes(0, 0, 0);
  end.setTime(end.getTime() - endOffsetHours * HOUR);
  const explicit = hours != null;
  const span = Math.min(Math.max(explicit ? hours : 1, 1), maxLookbackHours);
  let start = new Date(end.getTime() - span * HOUR);
  if (!explicit && stateEnd) {
    start = new Date(Math.max(new Date(stateEnd).getTime(), end.getTime() - maxLookbackHours * HOUR));
  }
  return { start, end, useState: !explicit, empty: start >= end };
}

const PRIVATE_V4 = /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;
const PRIVATE_V6 = /^(::1?$|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/i;

/** Private, loopback, link-local, CGNAT and ULA addresses are never reported. */
export function isPrivate(ip) {
  return ip.includes(":") ? PRIVATE_V6.test(ip) : PRIVATE_V4.test(ip);
}

/** Group firewall events by client IP. */
export function aggregate(events) {
  const byIp = new Map();
  for (const ev of events) {
    const e = byIp.get(ev.clientIP) ?? {
      count: 0,
      requests: new Set(),
      first: ev.datetime,
      asn: ev.clientAsn,
      country: ev.clientCountryName,
    };
    e.count++;
    e.requests.add(`${ev.clientRequestHTTPMethodName} ${ev.clientRequestPath}`);
    if (ev.datetime < e.first) e.first = ev.datetime;
    byIp.set(ev.clientIP, e);
  }
  return byIp;
}

/** AbuseIPDB comment, capped below the 1024-character limit. Placeholders: {count}, {requests}. */
export function buildComment(template, e, maxRequests = 8) {
  const list = [...e.requests];
  const more = list.length > maxRequests ? ` (+${list.length - maxRequests} more)` : "";
  let requests = list.slice(0, maxRequests).join(", ") + more;
  const fixed = template.replaceAll("{count}", String(e.count));
  // Shorten the request list rather than the end of the comment, so a trailing credit or note survives.
  const slots = fixed.split("{requests}").length - 1;
  if (slots) {
    const budget = Math.floor((1000 - (fixed.length - slots * "{requests}".length)) / slots);
    if (requests.length > budget) requests = requests.slice(0, Math.max(0, budget - 1)) + "…";
  }
  return fixed.replaceAll("{requests}", requests).slice(0, 1000);
}

export const CREDIT = " • Reported by: github.com/pfstr/cloudflare-abuseipdb-reporter";

/** Appends the credit line unless it is switched off or the template already names the project. */
export function withCredit(template, enabled = true) {
  return enabled && !template.includes("cloudflare-abuseipdb-reporter") ? template + CREDIT : template;
}

/** CSV in the format of https://www.abuseipdb.com/bulk-report */
export function toCsv(rows, categories) {
  const q = (v) => `"${String(v).replace(/"/g, '""')}"`;
  const lines = rows.map((r) => [r.ip, q(categories), r.date, q(r.comment)].join(","));
  return ["IP,Categories,ReportDate,Comment", ...lines].join("\n") + "\n";
}
