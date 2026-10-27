// WHY: Exercises the comparison's package-level matching and ensures OSV finding status 1 is accepted only with valid machine-readable output.

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { compareFindings, collectFindings, parseScanResult } = require('./compare-sbom-inventories');

const fixture = (name, version, id, aliases = []) => ({
  results: [{
    source: { path: name, type: 'sbom' },
    packages: [{
      package: { name, version, ecosystem: 'Maven' },
      vulnerabilities: [{ id, aliases }],
    }],
  }],
});

test('compares package findings through shared vulnerability aliases', () => {
  const before = collectFindings(fixture('org.example:legacy', '1.0', 'OSV-1', ['CVE-2026-0001']));
  const after = collectFindings(fixture('org.example:legacy', '1.0', 'GHSA-1', ['CVE-2026-0001']));
  const inventory = new Set(['Maven:org.example:legacy']);
  const delta = compareFindings(before, after, inventory, inventory);
  assert.equal(delta.eliminated.length, 0);
  assert.equal(delta.retained.length, 1);

  const removed = compareFindings(before, [], inventory, new Set());
  assert.equal(removed.eliminated.length, 1);
  assert.equal(removed.retained.length, 0);
});

test('does not call a finding eliminated when its component remains at another version', () => {
  const before = collectFindings(fixture('org.example:legacy', '1.0', 'OSV-1', ['CVE-2026-0001']));
  const delta = compareFindings(before, [], new Set(['Maven:org.example:legacy']), new Set(['Maven:org.example:legacy']));
  assert.equal(delta.eliminated.length, 0);
  assert.equal(delta.notObservedWithComponentRetained.length, 1);
});

test('treats exit status 1 with valid JSON as findings and rejects scanner errors', () => {
  const withFinding = fixture('org.example:legacy', '1.0', 'OSV-1');
  assert.deepEqual(parseScanResult({ status: 1, stdout: JSON.stringify(withFinding), stderr: '' }, 'baseline'), withFinding);
  assert.throws(() => parseScanResult({ status: 2, stdout: '{"results":[]}', stderr: 'database unavailable' }, 'baseline'), /exit status 2/);
  assert.throws(() => parseScanResult({ status: 1, stdout: 'not json', stderr: '' }, 'baseline'), /valid JSON/);
  assert.throws(() => parseScanResult({ status: 1, stdout: '{"results":[]}', stderr: '' }, 'baseline'), /without any JSON findings/);
  assert.throws(() => parseScanResult({ status: 0, stdout: JSON.stringify(withFinding), stderr: '' }, 'baseline'), /despite JSON findings/);
});

test('runs both scans against one executable and writes hash-backed audit evidence', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-compare-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const scanner = path.join(directory, 'fake-osv-scanner');
  const baseline = path.join(directory, 'baseline.cdx.json');
  const postElision = path.join(directory, 'post-elision.cdx.json');
  const output = path.join(directory, 'report');
  fs.writeFileSync(baseline, '{"bomFormat":"CycloneDX","components":[{"group":"org.example","name":"removed","version":"1"}]}\n');
  fs.writeFileSync(postElision, '{"bomFormat":"CycloneDX","components":[]}\n');
  fs.writeFileSync(scanner, `#!/usr/bin/env node\nconst fs = require('node:fs');\nconst args = process.argv.slice(2);\nif (args[0] === '--version') { process.stdout.write('osv-scanner fake 1.2.3\\n'); process.exit(0); }\nconst file = args[args.indexOf('-L') + 1];\nconst result = file.includes('baseline') ? { results: [{ source: { path: file, type: 'sbom' }, packages: [{ package: { name: 'org.example:removed', version: '1', ecosystem: 'Maven' }, vulnerabilities: [{ id: 'OSV-1', aliases: ['CVE-2026-0001'] }] }] }] } : { results: [] };\nprocess.stdout.write(JSON.stringify(result));\nprocess.exit(file.includes('baseline') ? 1 : 0);\n`);
  fs.chmodSync(scanner, 0o755);

  const result = spawnSync(process.execPath, [path.join(__dirname, 'compare-sbom-inventories.js'), baseline, postElision, '--output-dir', output], {
    encoding: 'utf8',
    env: { ...process.env, OSV_SCANNER_BIN: scanner },
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(fs.readFileSync(path.join(output, 'comparison-report.json'), 'utf8'));
  assert.equal(report.scanner.version, 'osv-scanner fake 1.2.3');
  assert.equal(report.comparison.eliminatedPackageFindings.length, 1);
  assert.match(report.comparison.note, /not VEX/);
  assert.equal(report.inventories.baseline.sha256.length, 64);
  assert.equal(report.vulnerabilityDatabase.revision, null);
  assert.ok(report.scanTimestamps.baseline.startedAt);
  assert.ok(report.scanTimestamps.postElision.completedAt);
  assert.ok(fs.existsSync(path.join(output, 'baseline-scan.json')));
  assert.ok(fs.existsSync(path.join(output, 'post-elision-scan.json')));
});
