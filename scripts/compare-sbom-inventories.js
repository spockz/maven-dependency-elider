#!/usr/bin/env node
// WHY: Compares OSV-Scanner package findings for two explicit CycloneDX inventories while retaining enough provenance to audit the result.

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function fail(message) {
  throw new Error(message);
}

function parseArgs(args) {
  const options = { baseline: null, postElision: null, outputDirectory: 'target/sbom-comparison' };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--output-dir') {
      options.outputDirectory = args[++index];
      if (!options.outputDirectory) fail('--output-dir requires a path');
    } else if (arg.startsWith('-')) {
      fail(`Unknown option: ${arg}`);
    } else if (options.baseline === null) {
      options.baseline = arg;
    } else if (options.postElision === null) {
      options.postElision = arg;
    } else {
      fail(`Unexpected argument: ${arg}`);
    }
  }
  if (!options.baseline || !options.postElision) {
    fail('Usage: compare-sbom-inventories.js <baseline-sbom> <post-elision-sbom> [--output-dir <directory>]');
  }
  return options;
}

function resolveExecutable(command, env = process.env) {
  const candidates = command.includes(path.sep)
    ? [path.resolve(command)]
    : (env.PATH || '').split(path.delimiter).map((directory) => path.join(directory || '.', command));
  const executable = candidates.find((candidate) => {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return fs.statSync(candidate).isFile();
    } catch {
      return false;
    }
  });
  if (!executable) fail(`OSV-Scanner executable not found: ${command}`);
  return fs.realpathSync(executable);
}

function runScanner(executable, args) {
  const result = spawnSync(executable, args, { encoding: 'utf8' });
  if (result.error) fail(`Could not execute OSV-Scanner: ${result.error.message}`);
  return result;
}

function parseScanResult(result, label) {
  if (result.status !== 0 && result.status !== 1) {
    fail(`OSV-Scanner ${label} scan failed with exit status ${result.status ?? 'unknown'}: ${(result.stderr || '').trim()}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch (error) {
    fail(`OSV-Scanner ${label} scan did not return valid JSON: ${error.message}`);
  }
  if (!parsed || !Array.isArray(parsed.results)) {
    fail(`OSV-Scanner ${label} scan JSON is missing the results array`);
  }
  if ((Array.isArray(parsed.errors) && parsed.errors.length > 0) || parsed.error) {
    fail(`OSV-Scanner ${label} scan reported errors in its JSON output`);
  }
  const hasFinding = parsed.results.some((result) => (result.packages || []).some((pkg) => (pkg.vulnerabilities || []).length > 0));
  if (result.status === 1 && !hasFinding) {
    fail(`OSV-Scanner ${label} scan exited 1 without any JSON findings`);
  }
  if (result.status === 0 && hasFinding) {
    fail(`OSV-Scanner ${label} scan exited 0 despite JSON findings`);
  }
  return parsed;
}

function hashFile(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function packageKey(pkg) {
  if (typeof pkg.purl === 'string' && pkg.purl.length > 0) return purlComponentKey(pkg.purl);
  if (pkg.name) return `${pkg.ecosystem ?? ''}:${pkg.name}`;
  return null;
}

function purlComponentKey(purl) {
  const fragmentIndex = purl.indexOf('#');
  const withoutFragment = fragmentIndex === -1 ? purl : purl.slice(0, fragmentIndex);
  const queryIndex = withoutFragment.indexOf('?');
  const pathAndVersion = queryIndex === -1 ? withoutFragment : withoutFragment.slice(0, queryIndex);
  const qualifiers = queryIndex === -1 ? '' : withoutFragment.slice(queryIndex + 1);
  const versionIndex = pathAndVersion.lastIndexOf('@');
  const pathWithoutVersion = versionIndex === -1 ? pathAndVersion : pathAndVersion.slice(0, versionIndex);
  const normalizedQualifiers = qualifiers.split('&').filter(Boolean).sort().join('&');
  return normalizedQualifiers ? `${pathWithoutVersion}?${normalizedQualifiers}` : pathWithoutVersion;
}

function inventoryComponentKeys(component) {
  const keys = new Set();
  if (typeof component.purl === 'string' && component.purl.length > 0) {
    const key = purlComponentKey(component.purl);
    keys.add(key);
    const mavenPurl = /^pkg:maven\/([^/]+)\/([^/?#]+)$/.exec(key);
    if (mavenPurl) keys.add(`Maven:${mavenPurl[1]}:${mavenPurl[2]}`);
  } else if (component.group && component.name) {
    keys.add(`Maven:${component.group}:${component.name}`);
  } else if (component.name) {
    keys.add(`${component.ecosystem ?? ''}:${component.name}`);
  }
  return keys;
}

function loadInventory(file, label) {
  let bom;
  try {
    bom = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    fail(`${label} SBOM is not valid JSON: ${error.message}`);
  }
  if (!bom || !Array.isArray(bom.components)) fail(`${label} SBOM JSON is missing the CycloneDX components array`);
  const components = new Set();
  const visit = (entries) => {
    for (const component of entries) {
      for (const key of inventoryComponentKeys(component)) components.add(key);
      if (Array.isArray(component.components)) visit(component.components);
    }
  };
  visit(bom.components);
  return components;
}

function vulnerabilityIds(vulnerability) {
  return [...new Set([vulnerability.id, ...(Array.isArray(vulnerability.aliases) ? vulnerability.aliases : [])]
    .filter((id) => typeof id === 'string' && id.length > 0))].sort();
}

function collectFindings(scan) {
  const findings = [];
  for (const result of scan.results) {
    for (const packageResult of result.packages || []) {
      const pkg = packageResult.package || {};
      const identity = packageKey(pkg);
      for (const vulnerability of packageResult.vulnerabilities || []) {
        const ids = vulnerabilityIds(vulnerability);
        if (ids.length === 0) fail(`OSV-Scanner returned a vulnerability without an identifier for ${identity}`);
        findings.push({
          package: identity,
          name: pkg.name ?? null,
          ecosystem: pkg.ecosystem ?? null,
          version: pkg.version ?? null,
          vulnerabilityIds: ids,
          source: result.source?.path ?? null,
        });
      }
    }
  }
  return findings;
}

function findingMatches(left, right) {
  if (left.package !== right.package) return false;
  const ids = new Set(left.vulnerabilityIds);
  return right.vulnerabilityIds.some((id) => ids.has(id));
}

function compareFindings(baseline, postElision, baselineInventory, postInventory) {
  const remaining = [...postElision];
  const eliminated = [];
  const retained = [];
  const notObservedWithComponentRetained = [];
  const unclassified = [];
  for (const finding of baseline) {
    const matchIndex = remaining.findIndex((candidate) => findingMatches(finding, candidate));
    if (matchIndex === -1) {
      if (finding.package === null || !baselineInventory.has(finding.package)) {
        unclassified.push(finding);
      } else if (postInventory.has(finding.package)) {
        notObservedWithComponentRetained.push(finding);
      } else {
        eliminated.push(finding);
      }
    } else {
      retained.push(finding);
      remaining.splice(matchIndex, 1);
    }
  }
  return { eliminated, retained, notObservedWithComponentRetained, postElisionOnly: remaining, unclassified };
}

function escapeTable(value) {
  return String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function formatTable(comparison) {
  const rows = [
    ['Status', 'Package', 'Version', 'Finding identifiers'],
    ['---', '---', '---', '---'],
  ];
  for (const [status, findings] of [
    ['Eliminated package findings (component absent)', comparison.eliminated],
    ['Finding not observed (component retained)', comparison.notObservedWithComponentRetained],
    ['Retained findings', comparison.retained],
    ['Post-elision only', comparison.postElisionOnly],
    ['Unclassified baseline findings', comparison.unclassified],
  ]) {
    for (const finding of findings) {
      rows.push([status, finding.name ?? finding.package, finding.version ?? '', finding.vulnerabilityIds.join(', ')]);
    }
  }
  if (rows.length === 2) rows.push(['No findings', '', '', '']);
  return rows.map((row) => `| ${row.map(escapeTable).join(' | ')} |`).join('\n');
}

function scanOne(executable, file, label) {
  const startedAt = new Date().toISOString();
  const result = runScanner(executable, ['scan', 'source', '--offline-vulnerabilities', '--format', 'json', '-L', file]);
  const scan = parseScanResult(result, label);
  return { scan, startedAt, completedAt: new Date().toISOString() };
}

function main(args = process.argv.slice(2), env = process.env) {
  const options = parseArgs(args);
  const baselinePath = path.resolve(options.baseline);
  const postElisionPath = path.resolve(options.postElision);
  for (const [label, file] of [['baseline', baselinePath], ['post-elision', postElisionPath]]) {
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) fail(`${label} SBOM does not exist or is not a file: ${file}`);
  }

  const executable = resolveExecutable(env.OSV_SCANNER_BIN || 'osv-scanner', env);
  const versionResult = runScanner(executable, ['--version']);
  if (versionResult.status !== 0) fail(`Could not read OSV-Scanner version (exit ${versionResult.status}): ${(versionResult.stderr || '').trim()}`);
  const scannerVersion = `${versionResult.stdout}${versionResult.stderr}`.trim();
  if (!scannerVersion) fail('OSV-Scanner returned an empty version string');

  const baselineResult = scanOne(executable, baselinePath, 'baseline');
  const postElisionResult = scanOne(executable, postElisionPath, 'post-elision');
  const scannedAt = new Date().toISOString();
  const baselineInventory = loadInventory(baselinePath, 'baseline');
  const postInventory = loadInventory(postElisionPath, 'post-elision');
  const comparison = compareFindings(collectFindings(baselineResult.scan), collectFindings(postElisionResult.scan), baselineInventory, postInventory);
  const outputDirectory = path.resolve(options.outputDirectory);
  fs.mkdirSync(outputDirectory, { recursive: true });
  fs.writeFileSync(path.join(outputDirectory, 'baseline-scan.json'), `${JSON.stringify(baselineResult.scan, null, 2)}\n`);
  fs.writeFileSync(path.join(outputDirectory, 'post-elision-scan.json'), `${JSON.stringify(postElisionResult.scan, null, 2)}\n`);
  const report = {
    scannedAt,
    scanTimestamps: {
      baseline: { startedAt: baselineResult.startedAt, completedAt: baselineResult.completedAt },
      postElision: { startedAt: postElisionResult.startedAt, completedAt: postElisionResult.completedAt },
    },
    scanner: { executable, version: scannerVersion },
    vulnerabilityDatabase: {
      mode: 'offline shared local database',
      revision: null,
      note: 'OSV-Scanner did not expose a database revision in this run; matching local data is not independently verified.',
    },
    inventories: {
      baseline: { path: baselinePath, sha256: hashFile(baselinePath) },
      postElision: { path: postElisionPath, sha256: hashFile(postElisionPath) },
      baselineComponentCount: baselineInventory.size,
      postElisionComponentCount: postInventory.size,
    },
    comparison: {
      scope: 'package-level findings matched to inventory components',
      eliminatedPackageFindings: comparison.eliminated,
      findingsNotObservedWithComponentRetained: comparison.notObservedWithComponentRetained,
      retainedFindings: comparison.retained,
      postElisionOnlyFindings: comparison.postElisionOnly,
      unclassifiedBaselineFindings: comparison.unclassified,
      note: 'An eliminated package finding is reported only when its package component is absent from the post-elision SBOM. A finding no longer returned for a component still present is reported separately. Neither result proves vulnerable code was removed or that the product is unaffected; this report is not VEX.',
    },
  };
  fs.writeFileSync(path.join(outputDirectory, 'comparison-report.json'), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${formatTable(comparison)}\n\nAudit report: ${path.join(outputDirectory, 'comparison-report.json')}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`SBOM comparison failed: ${error.message}\n`);
    process.exitCode = 2;
  }
}

module.exports = { compareFindings, collectFindings, parseScanResult };
