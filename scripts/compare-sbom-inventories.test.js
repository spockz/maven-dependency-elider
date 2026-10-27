// WHY: Exercises the comparison's package-level matching and ensures OSV finding status 1 is accepted only with valid machine-readable output.

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { compareFindings, collectFindings, parseScanResult } = require('./compare-sbom-inventories');

const fixture = (name, version, id, aliases = [], purl = undefined) => ({
  results: [{
    source: { path: name, type: 'sbom' },
    packages: [{
      package: { name, version, ecosystem: 'Maven', ...(purl ? { purl } : {}) },
      vulnerabilities: [{ id, aliases }],
    }],
  }],
});

function inventory(entries) {
  return { components: entries.map(({ key, version, lookup = 'Maven:org.example:legacy' }) => ({
    key,
    version,
    lookupKeys: new Set([lookup]),
  })), count: entries.length };
}

function writeFakeScanner(directory) {
  const scanner = path.join(directory, 'fake-osv-scanner');
  fs.writeFileSync(scanner, `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === '--version') { process.stdout.write('osv-scanner fake 1.2.3\\n'); process.exit(0); }
if (process.env.FAKE_ARG_LOG) fs.appendFileSync(process.env.FAKE_ARG_LOG, JSON.stringify(args) + '\\n');
if (process.env.FAKE_SCANNER_ERROR === '1') { process.stderr.write('database unavailable\\n'); process.exit(2); }
const file = args[args.indexOf('-L') + 1];
if (process.env.FAKE_MUTATE_FILE === file) fs.writeFileSync(file, '{"bomFormat":"CycloneDX","components":[{"name":"changed"}]}\\n');
const baseline = file.endsWith('baseline.cdx.json');
const result = JSON.parse(baseline ? (process.env.FAKE_BASELINE_RESULT || '{"results":[]}') : (process.env.FAKE_POST_RESULT || '{"results":[]}'));
process.stdout.write(JSON.stringify(result));
process.exit(result.results.some((entry) => (entry.packages || []).some((pkg) => (pkg.vulnerabilities || []).length > 0)) ? 1 : 0);
`);
  fs.chmodSync(scanner, 0o755);
  return scanner;
}

function runCli({ directory, scanner, baseline, postElision, output, env = {} }) {
  return spawnSync(process.execPath, [path.join(__dirname, 'compare-sbom-inventories.js'), baseline, postElision, '--output-dir', output], {
    encoding: 'utf8',
    env: { ...process.env, OSV_SCANNER_BIN: scanner, ...env },
  });
}

test('compares package findings through shared vulnerability aliases', () => {
  const bomInventory = inventory([{ key: 'pkg:maven/org.example/legacy', version: '1.0' }]);
  const before = collectFindings(fixture('org.example:legacy', '1.0', 'OSV-1', ['CVE-2026-0001']), bomInventory);
  const after = collectFindings(fixture('org.example:legacy', '1.0', 'GHSA-1', ['CVE-2026-0001']), bomInventory);
  const delta = compareFindings(before, after, bomInventory);
  assert.equal(delta.eliminated.length, 0);
  assert.equal(delta.retained.length, 1);

  const removed = compareFindings(before, [], inventory([]));
  assert.equal(removed.eliminated.length, 1);
  assert.equal(removed.retained.length, 0);
});

test('does not call a finding eliminated when its component remains at another version', () => {
  const baselineInventory = inventory([{ key: 'pkg:maven/org.example/legacy', version: '1.0' }]);
  const postInventory = inventory([{ key: 'pkg:maven/org.example/legacy', version: '2.0' }]);
  const before = collectFindings(fixture('org.example:legacy', '1.0', 'OSV-1', ['CVE-2026-0001']), baselineInventory);
  const delta = compareFindings(before, [], postInventory);
  assert.equal(delta.eliminated.length, 0);
  assert.equal(delta.notObservedWithComponentRetained.length, 1);
});

test('CLI marks legacy Maven findings ambiguous across ordinary and classifier PURLs, and preserves changed-version components', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-identity-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const scanner = writeFakeScanner(directory);
  const findingScan = fixture('org.example:legacy', '1.0', 'OSV-1');
  const bom = (components) => JSON.stringify({ bomFormat: 'CycloneDX', components });
  const ordinaryV1 = { group: 'org.example', name: 'legacy', version: '1.0', purl: 'pkg:maven/org.example/legacy@1.0' };
  const ordinaryV2 = { ...ordinaryV1, version: '2.0', purl: 'pkg:maven/org.example/legacy@2.0' };
  const classifierV1 = { ...ordinaryV1, purl: 'pkg:maven/org.example/legacy@1.0?classifier=sources' };

  const ambiguousDirectory = path.join(directory, 'ambiguous');
  fs.mkdirSync(ambiguousDirectory);
  const ambiguousBaseline = path.join(ambiguousDirectory, 'baseline.cdx.json');
  const ambiguousPost = path.join(ambiguousDirectory, 'post-elision.cdx.json');
  const ambiguousOutput = path.join(ambiguousDirectory, 'report');
  fs.writeFileSync(ambiguousBaseline, bom([ordinaryV1, classifierV1]));
  fs.writeFileSync(ambiguousPost, bom([ordinaryV2]));
  const ambiguousResult = runCli({
    directory,
    scanner,
    baseline: ambiguousBaseline,
    postElision: ambiguousPost,
    output: ambiguousOutput,
    env: { FAKE_BASELINE_RESULT: JSON.stringify(findingScan) },
  });
  assert.equal(ambiguousResult.status, 0, ambiguousResult.stderr);
  const ambiguousReport = JSON.parse(fs.readFileSync(path.join(ambiguousOutput, 'comparison-report.json'), 'utf8'));
  assert.equal(ambiguousReport.comparison.eliminatedPackageFindings.length, 0);
  assert.equal(ambiguousReport.comparison.unclassifiedBaselineFindings.length, 1);
  assert.equal(ambiguousReport.inventories.baselineComponentCount, 2);
  assert.equal(ambiguousReport.inventories.postElisionComponentCount, 1);

  const changedVersionDirectory = path.join(directory, 'changed-version');
  fs.mkdirSync(changedVersionDirectory);
  const changedBaseline = path.join(changedVersionDirectory, 'baseline.cdx.json');
  const changedPost = path.join(changedVersionDirectory, 'post-elision.cdx.json');
  const changedOutput = path.join(changedVersionDirectory, 'report');
  fs.writeFileSync(changedBaseline, bom([ordinaryV1]));
  fs.writeFileSync(changedPost, bom([ordinaryV2]));
  const changedResult = runCli({
    directory,
    scanner,
    baseline: changedBaseline,
    postElision: changedPost,
    output: changedOutput,
    env: { FAKE_BASELINE_RESULT: JSON.stringify(findingScan) },
  });
  assert.equal(changedResult.status, 0, changedResult.stderr);
  const changedReport = JSON.parse(fs.readFileSync(path.join(changedOutput, 'comparison-report.json'), 'utf8'));
  assert.equal(changedReport.comparison.eliminatedPackageFindings.length, 0);
  assert.equal(changedReport.comparison.findingsNotObservedWithComponentRetained.length, 1);
  assert.equal(changedReport.inventories.baselineComponentCount, 1);
  assert.equal(changedReport.inventories.postElisionComponentCount, 1);
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
  const scanner = writeFakeScanner(directory);
  const baseline = path.join(directory, 'baseline.cdx.json');
  const postElision = path.join(directory, 'post-elision.cdx.json');
  const output = path.join(directory, 'report');
  const argumentLog = path.join(directory, 'scanner-arguments.jsonl');
  fs.writeFileSync(baseline, '{"bomFormat":"CycloneDX","components":[{"group":"org.example","name":"removed","version":"1"}]}\n');
  fs.writeFileSync(postElision, '{"bomFormat":"CycloneDX","components":[]}\n');
  const result = runCli({
    directory,
    scanner,
    baseline,
    postElision,
    output,
    env: {
      FAKE_ARG_LOG: argumentLog,
      FAKE_BASELINE_RESULT: JSON.stringify(fixture('org.example:removed', '1', 'OSV-1', ['CVE-2026-0001'])),
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(fs.readFileSync(path.join(output, 'comparison-report.json'), 'utf8'));
  assert.equal(report.scanner.version, 'osv-scanner fake 1.2.3');
  assert.equal(report.comparison.eliminatedPackageFindings.length, 1);
  assert.match(report.comparison.note, /not VEX/);
  assert.equal(report.inventories.baseline.sha256.length, 64);
  assert.equal(report.inventories.baselineComponentCount, 1);
  assert.equal(report.inventories.postElisionComponentCount, 0);
  assert.equal(report.vulnerabilityDatabase.revision, null);
  assert.ok(report.scanTimestamps.baseline.startedAt);
  assert.ok(report.scanTimestamps.postElision.completedAt);
  assert.ok(fs.existsSync(path.join(output, 'baseline-scan.json')));
  assert.ok(fs.existsSync(path.join(output, 'post-elision-scan.json')));
  const calls = fs.readFileSync(argumentLog, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(calls.length, 2);
  for (const args of calls) {
    assert.ok(args.includes('scan'));
    assert.ok(args.includes('source'));
    assert.ok(args.includes('--offline-vulnerabilities'));
    assert.ok(args.includes('--format'));
    assert.ok(args.includes('json'));
    assert.ok(args.includes('-L'));
  }
});

test('rejects an SBOM that changes while OSV-Scanner is reading it', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-mutation-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const scanner = writeFakeScanner(directory);
  const baseline = path.join(directory, 'baseline.cdx.json');
  const postElision = path.join(directory, 'post-elision.cdx.json');
  const output = path.join(directory, 'report');
  fs.writeFileSync(baseline, '{"bomFormat":"CycloneDX","components":[]}\n');
  fs.writeFileSync(postElision, '{"bomFormat":"CycloneDX","components":[]}\n');
  const result = runCli({
    directory,
    scanner,
    baseline,
    postElision,
    output,
    env: { FAKE_MUTATE_FILE: baseline },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /baseline SBOM changed during its scan/);
});

test('propagates scanner execution failures through the CLI', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-scanner-error-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const scanner = writeFakeScanner(directory);
  const baseline = path.join(directory, 'baseline.cdx.json');
  const postElision = path.join(directory, 'post-elision.cdx.json');
  const output = path.join(directory, 'report');
  fs.writeFileSync(baseline, '{"bomFormat":"CycloneDX","components":[]}\n');
  fs.writeFileSync(postElision, '{"bomFormat":"CycloneDX","components":[]}\n');
  const result = runCli({ directory, scanner, baseline, postElision, output, env: { FAKE_SCANNER_ERROR: '1' } });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /exit status 2: database unavailable/);
});
