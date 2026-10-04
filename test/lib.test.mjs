import { test } from "node:test";
import assert from "node:assert/strict";
import { aggregate, buildComment, computeWindow, isPrivate, toCsv } from "../src/lib.mjs";

const now = new Date("2026-10-03T14:27:00Z");
const iso = (d) => d.toISOString();

test("first run without state covers the last full hour", () => {
  const w = computeWindow({ now });
  assert.equal(iso(w.start), "2026-10-03T13:00:00.000Z");
  assert.equal(iso(w.end), "2026-10-03T14:00:00.000Z");
  assert.equal(w.useState, true);
});

test("state catches up on missed runs", () => {
  const w = computeWindow({ now, stateEnd: "2026-10-03T11:00:00.000Z" });
  assert.equal(iso(w.start), "2026-10-03T11:00:00.000Z");
  assert.equal(iso(w.end), "2026-10-03T14:00:00.000Z");
});

test("catch-up is capped at maxLookbackHours", () => {
  const w = computeWindow({ now, stateEnd: "2026-09-01T00:00:00.000Z", maxLookbackHours: 72 });
  assert.equal(iso(w.start), "2026-09-30T14:00:00.000Z");
});

test("nothing to do when state is current", () => {
  assert.equal(computeWindow({ now, stateEnd: "2026-10-03T14:00:00.000Z" }).empty, true);
});

test("explicit hours ignore the state and honour the end offset", () => {
  const w = computeWindow({ now, stateEnd: "2026-10-03T14:00:00.000Z", hours: 48, endOffsetHours: 24 });
  assert.equal(iso(w.start), "2026-09-30T14:00:00.000Z");
  assert.equal(iso(w.end), "2026-10-02T14:00:00.000Z");
  assert.equal(w.useState, false);
});

test("private and special addresses", () => {
  for (const ip of ["10.1.2.3", "127.0.0.1", "192.168.0.48", "172.16.0.1", "172.31.255.1", "169.254.1.1", "100.64.0.1",
    "100.127.255.255", "::1", "fd12:3456::1", "fe80::1"]) {
    assert.equal(isPrivate(ip), true, ip);
  }
  for (const ip of ["20.194.96.114", "172.32.0.1", "100.128.0.1", "8.8.8.8", "2405:201:5006:7133::1", "2a01:4f8::1"]) {
    assert.equal(isPrivate(ip), false, ip);
  }
});

test("aggregate groups by IP and keeps the earliest timestamp", () => {
  const ev = (ip, t, path) => ({ clientIP: ip, datetime: t, clientRequestPath: path, clientRequestHTTPMethodName: "GET",
    clientAsn: "8075", clientCountryName: "KR" });
  const m = aggregate([
    ev("1.2.3.4", "2026-10-03T12:00:05Z", "/.env"),
    ev("1.2.3.4", "2026-10-03T12:00:01Z", "/.env"),
    ev("1.2.3.4", "2026-10-03T12:00:09Z", "/wp-login.php"),
    ev("5.6.7.8", "2026-10-03T12:01:00Z", "/xmlrpc.php"),
  ]);
  assert.equal(m.size, 2);
  const a = m.get("1.2.3.4");
  assert.equal(a.count, 3);
  assert.equal(a.first, "2026-10-03T12:00:01Z");
  assert.deepEqual([...a.requests], ["GET /.env", "GET /wp-login.php"]);
});

test("comment fills placeholders and truncates the request list", () => {
  const e = { count: 12, requests: new Set(Array.from({ length: 10 }, (_, i) => `GET /p${i}`)) };
  const c = buildComment("{count} hits: {requests}", e);
  assert.match(c, /^12 hits: GET \/p0, /);
  assert.match(c, /\(\+2 more\)$/);
  assert.ok(buildComment("{requests}".repeat(50), e).length <= 1000);
});

test("long request lists are shortened so the end of the comment survives", () => {
  const e = { count: 3, requests: new Set(Array.from({ length: 3 }, (_, i) => `GET /${"x".repeat(400)}${i}`)) };
  const c = buildComment("Blocked: {requests} • Reported by example", e);
  assert.ok(c.length <= 1000);
  assert.match(c, /… • Reported by example$/);
});

test("csv escapes quotes", () => {
  const csv = toCsv([{ ip: "1.2.3.4", date: "2026-10-03T12:00:00Z", comment: 'say "hi"' }], "21,15");
  assert.equal(csv, 'IP,Categories,ReportDate,Comment\n1.2.3.4,"21,15",2026-10-03T12:00:00Z,"say ""hi"""\n');
});
