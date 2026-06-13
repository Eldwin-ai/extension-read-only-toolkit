import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseAllDocuments } from "yaml";
import { z } from "zod";

export const DEFAULT_SCAN_LIMIT_BYTES = 256 * 1024 * 1024;
const MAX_SCAN_LIMIT_BYTES = 2 * 1024 * 1024 * 1024;
const OUTPUT_CHAR_LIMIT = 60_000;
const SENSITIVE_FILE_PATTERN =
  /(^|[/\\])(\.env([./\\]|$)|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|.*\.(pem|key|p12|pfx|crt)$|kubeconfig$|credentials?$|secrets?(\.|$))/i;

export const filePathSchema = z
  .string()
  .min(1)
  .describe("Absolute path, or a path relative to the agent working directory.");

export const scanLimitSchema = z
  .number()
  .int()
  .positive()
  .max(MAX_SCAN_LIMIT_BYTES)
  .default(DEFAULT_SCAN_LIMIT_BYTES)
  .describe("Maximum bytes to stream from the file.");

export const allowSensitiveSchema = z
  .boolean()
  .default(false)
  .describe("Set true only after explicit user approval to inspect paths that look like secrets or credentials.");

export function ok(text) {
  return { content: [{ type: "text", text: truncate(text) }] };
}

export function fail(error) {
  return {
    isError: true,
    content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }]
  };
}

export function defineReadOnlyTool(tool) {
  return {
    ...tool,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      ...(tool.annotations ?? {})
    }
  };
}

export function assertNonHtmlApiResponse(provider, text) {
  const body = String(text || "");
  const head = body.slice(0, 1000).toLowerCase();
  if (/<html\b|<!doctype html\b|<form\b|login|atlassian-token|ajs-/.test(head)) {
    throw new Error(`${provider} API returned an HTML login or browser page instead of API data. Authentication/session refresh must be handled outside this read-only tool with human-in-the-loop approval. HTML body was suppressed.`);
  }
}

function truncate(text) {
  if (text.length <= OUTPUT_CHAR_LIMIT) {
    return text;
  }
  return `${text.slice(0, OUTPUT_CHAR_LIMIT)}\n\n[output truncated at ${OUTPUT_CHAR_LIMIT} characters]`;
}

function resolveFilePath(filePath) {
  return isAbsolute(filePath) ? filePath : resolve(process.cwd(), filePath);
}

async function assertReadableFile(filePath, allowSensitive = false) {
  const resolvedPath = resolveFilePath(filePath);
  if (!allowSensitive && SENSITIVE_FILE_PATTERN.test(resolvedPath)) {
    throw new Error("Refusing to read a path that looks sensitive. Re-run only with explicit user approval and allowSensitive=true.");
  }

  const stat = await fs.stat(resolvedPath);
  if (!stat.isFile()) {
    throw new Error(`${resolvedPath} is not a regular file.`);
  }

  return { resolvedPath, stat };
}

async function streamLines(filePath, scanLimitBytes, onLine) {
  const stream = createReadStream(filePath, {
    encoding: "utf8",
    highWaterMark: 1024 * 1024
  });
  const reader = createInterface({ input: stream, crlfDelay: Infinity });
  let bytesScanned = 0;
  let lineNumber = 0;
  let truncatedByScanLimit = false;

  try {
    for await (const line of reader) {
      bytesScanned += Buffer.byteLength(`${line}\n`);
      if (bytesScanned > scanLimitBytes) {
        truncatedByScanLimit = true;
        reader.close();
        stream.destroy();
        break;
      }

      lineNumber += 1;
      await onLine(line, lineNumber);
    }
  } finally {
    reader.close();
    stream.destroy();
  }

  return { bytesScanned, lineNumber, truncatedByScanLimit };
}

function getPathValue(value, path) {
  return path.split(".").reduce((current, part) => {
    if (current === undefined || current === null) {
      return undefined;
    }
    return current[part];
  }, value);
}

function increment(map, key) {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function renderTopMap(title, map, limit = 20) {
  const entries = [...map.entries()].sort((left, right) => right[1] - left[1]).slice(0, limit);
  if (entries.length === 0) {
    return `${title}\n- none`;
  }
  return [title, ...entries.map(([key, count]) => `- ${key}: ${count}`)].join("\n");
}

export async function logPatternSummary(input) {
  const {
    allowSensitive = false,
    filePath,
    maxSamplesPerPattern = 5,
    patterns = [
      "ERROR",
      "WARN",
      "Exception",
      "Traceback",
      "timeout",
      "connection refused",
      "5\\d\\d",
      "OOMKilled",
      "CrashLoopBackOff"
    ],
    scanLimitBytes = DEFAULT_SCAN_LIMIT_BYTES
  } = input;
  const { resolvedPath, stat } = await assertReadableFile(filePath, allowSensitive);
  const compiled = patterns.map((pattern) => ({ pattern, regex: new RegExp(pattern, "i"), count: 0, samples: [] }));
  let firstTimestamp;
  let lastTimestamp;
  const timestampRegex = /\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b/;

  const scan = await streamLines(resolvedPath, scanLimitBytes, (line, lineNumber) => {
    const timestamp = line.match(timestampRegex)?.[0];
    if (timestamp) {
      firstTimestamp ??= timestamp;
      lastTimestamp = timestamp;
    }

    for (const item of compiled) {
      if (item.regex.test(line)) {
        item.count += 1;
        if (item.samples.length < maxSamplesPerPattern) {
          item.samples.push(`${lineNumber}: ${line}`);
        }
      }
    }
  });

  return [
    `path: ${resolvedPath}`,
    `sizeBytes: ${stat.size}`,
    `bytesScanned: ${scan.bytesScanned}`,
    `linesScanned: ${scan.lineNumber}`,
    `truncatedByScanLimit: ${scan.truncatedByScanLimit}`,
    `firstTimestampSeen: ${firstTimestamp ?? "unknown"}`,
    `lastTimestampSeen: ${lastTimestamp ?? "unknown"}`,
    "",
    "patternCounts:",
    ...compiled.map((item) => `- /${item.pattern}/i: ${item.count}`),
    "",
    "samples:",
    ...compiled.flatMap((item) => [
      `## /${item.pattern}/i`,
      item.samples.length ? item.samples.join("\n") : "(no samples)"
    ])
  ].join("\n");
}

export async function jsonLogAnalyze(input) {
  const {
    allowSensitive = false,
    filePath,
    groupBy = ["level", "status", "service"],
    maxErrorSamples = 20,
    scanLimitBytes = DEFAULT_SCAN_LIMIT_BYTES
  } = input;
  const { resolvedPath, stat } = await assertReadableFile(filePath, allowSensitive);
  const fieldCounts = new Map(groupBy.map((field) => [field, new Map()]));
  const errorSamples = [];
  let parsedLines = 0;
  let invalidJsonLines = 0;

  const scan = await streamLines(resolvedPath, scanLimitBytes, (line, lineNumber) => {
    if (!line.trim()) {
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(line);
      parsedLines += 1;
    } catch {
      invalidJsonLines += 1;
      return;
    }

    for (const field of groupBy) {
      const value = getPathValue(parsed, field);
      if (value !== undefined) {
        increment(fieldCounts.get(field), String(value));
      }
    }

    const level = String(getPathValue(parsed, "level") ?? getPathValue(parsed, "severity") ?? "").toLowerCase();
    const status = Number(getPathValue(parsed, "status") ?? getPathValue(parsed, "statusCode") ?? 0);
    const message = String(getPathValue(parsed, "message") ?? getPathValue(parsed, "msg") ?? getPathValue(parsed, "error.message") ?? "");
    if ((level && ["error", "fatal", "warn", "warning"].includes(level)) || status >= 400 || /error|exception|timeout/i.test(message)) {
      if (errorSamples.length < maxErrorSamples) {
        errorSamples.push(`${lineNumber}: ${line}`);
      }
    }
  });

  return [
    `path: ${resolvedPath}`,
    `sizeBytes: ${stat.size}`,
    `bytesScanned: ${scan.bytesScanned}`,
    `linesScanned: ${scan.lineNumber}`,
    `parsedJsonLines: ${parsedLines}`,
    `invalidJsonLines: ${invalidJsonLines}`,
    `truncatedByScanLimit: ${scan.truncatedByScanLimit}`,
    "",
    ...[...fieldCounts.entries()].map(([field, map]) => renderTopMap(`top ${field}:`, map)),
    "",
    "errorSamples:",
    errorSamples.length ? errorSamples.join("\n") : "(none)"
  ].join("\n");
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = Date.now();
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const durationMs = Date.now() - startedAt;
    return { response, durationMs };
  } finally {
    clearTimeout(timer);
  }
}

function selectedHeaders(headers, names = []) {
  const selected = {};
  const wanted = names.length ? names : ["content-type", "cache-control", "location", "server", "x-request-id"];
  for (const name of wanted) {
    const value = headers.get(name);
    if (value !== null) {
      selected[name.toLowerCase()] = value;
    }
  }
  return selected;
}

async function responseSummary(url, input = {}) {
  const method = input.method ?? "GET";
  const { response, durationMs } = await fetchWithTimeout(url, { method }, input.timeoutMs ?? 15_000);
  const body = method === "HEAD" ? "" : await response.text();
  const bodyPreviewLimit = input.bodyPreviewChars ?? 2_000;
  const bodyHash = createHash("sha256").update(body).digest("hex");
  let json;
  try {
    json = body ? JSON.parse(body) : undefined;
  } catch {
    json = undefined;
  }

  return {
    bodyHash,
    bodyPreview: body.slice(0, bodyPreviewLimit),
    durationMs,
    headers: selectedHeaders(response.headers, input.headers),
    json,
    status: response.status,
    statusText: response.statusText,
    url: response.url
  };
}

export async function httpProbe(input) {
  const summary = await responseSummary(input.url, input);
  return JSON.stringify(summary, null, 2);
}

function walkManifests(value, visit, path = []) {
  if (!value || typeof value !== "object") {
    return;
  }
  visit(value, path);
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkManifests(item, visit, [...path, String(index)]));
  } else {
    Object.entries(value).forEach(([key, item]) => walkManifests(item, visit, [...path, key]));
  }
}

export async function kubeManifestLintReadonly(input) {
  const { allowSensitive = false, filePath } = input;
  const { resolvedPath } = await assertReadableFile(filePath, allowSensitive);
  const text = await fs.readFile(resolvedPath, "utf8");
  const docs = parseAllDocuments(text).map((doc) => doc.toJSON()).filter(Boolean);
  const findings = [];

  for (const doc of docs) {
    const kind = doc.kind ?? "Unknown";
    const name = doc.metadata?.name ?? "unnamed";
    walkManifests(doc, (node, path) => {
      const pathText = path.join(".");
      if (node.image && typeof node.image === "string" && /:latest$|^[^:]+$/.test(node.image)) {
        findings.push(`[image] ${kind}/${name} ${pathText}.image uses an unpinned or latest tag: ${node.image}`);
      }
      if (node.privileged === true) {
        findings.push(`[security] ${kind}/${name} ${pathText}.privileged is true`);
      }
      if (node.hostPath) {
        findings.push(`[security] ${kind}/${name} ${pathText}.hostPath is used`);
      }
      if (node.containers && Array.isArray(node.containers)) {
        for (const container of node.containers) {
          const containerName = container.name ?? "unnamed-container";
          if (!container.resources) {
            findings.push(`[resources] ${kind}/${name} container ${containerName} has no resources block`);
          }
          if (!container.livenessProbe && !container.readinessProbe && kind !== "Job" && kind !== "CronJob") {
            findings.push(`[probes] ${kind}/${name} container ${containerName} has no liveness/readiness probe`);
          }
          if (!container.securityContext && !doc.spec?.template?.spec?.securityContext) {
            findings.push(`[security] ${kind}/${name} container ${containerName} has no securityContext`);
          }
        }
      }
    });
  }

  return [
    `path: ${resolvedPath}`,
    `documents: ${docs.length}`,
    `findings: ${findings.length}`,
    "",
    findings.length ? findings.join("\n") : "No common manifest hygiene findings."
  ].join("\n");
}

export async function ciLogSummary(input) {
  const { allowSensitive = false, filePath, scanLimitBytes = DEFAULT_SCAN_LIMIT_BYTES } = input;
  const { resolvedPath, stat } = await assertReadableFile(filePath, allowSensitive);
  const errorRegex = /\b(error|failed|failure|exception|traceback|exited with code|npm ERR!|fatal:)\b/i;
  const stepRegex = /(?:^|\s)(?:##\[group\]|##\[section\]|Step \d+\/\d+|Running step|Run )(.{1,160})/i;
  const errors = [];
  const stepCounts = new Map();
  let currentStep = "unknown";

  const scan = await streamLines(resolvedPath, scanLimitBytes, (line, lineNumber) => {
    const stepMatch = line.match(stepRegex);
    if (stepMatch?.[1]) {
      currentStep = stepMatch[1].trim();
      increment(stepCounts, currentStep);
    }
    if (errorRegex.test(line) && errors.length < 80) {
      errors.push(`${lineNumber} [${currentStep}]: ${line}`);
    }
  });

  return [
    `path: ${resolvedPath}`,
    `sizeBytes: ${stat.size}`,
    `bytesScanned: ${scan.bytesScanned}`,
    `linesScanned: ${scan.lineNumber}`,
    `truncatedByScanLimit: ${scan.truncatedByScanLimit}`,
    "",
    renderTopMap("topStepsSeen:", stepCounts, 15),
    "",
    "failureLines:",
    errors.length ? errors.join("\n") : "(none)"
  ].join("\n");
}

function diffObject(left, right) {
  const keys = [...new Set([...Object.keys(left ?? {}), ...Object.keys(right ?? {})])].sort();
  return keys
    .filter((key) => left?.[key] !== right?.[key])
    .map((key) => `- ${key}: left=${JSON.stringify(left?.[key])} right=${JSON.stringify(right?.[key])}`);
}

export async function endpointDiff(input) {
  const left = await responseSummary(input.leftUrl, input);
  const right = await responseSummary(input.rightUrl, input);
  const jsonFields = input.jsonFields ?? [];
  const leftJson = Object.fromEntries(jsonFields.map((field) => [field, getPathValue(left.json, field)]));
  const rightJson = Object.fromEntries(jsonFields.map((field) => [field, getPathValue(right.json, field)]));

  return [
    `leftUrl: ${left.url}`,
    `rightUrl: ${right.url}`,
    `leftStatus: ${left.status} ${left.statusText}`,
    `rightStatus: ${right.status} ${right.statusText}`,
    `leftDurationMs: ${left.durationMs}`,
    `rightDurationMs: ${right.durationMs}`,
    `leftBodySha256: ${left.bodyHash}`,
    `rightBodySha256: ${right.bodyHash}`,
    `bodyHashesEqual: ${left.bodyHash === right.bodyHash}`,
    "",
    "headerDiffs:",
    diffObject(left.headers, right.headers).join("\n") || "(none)",
    "",
    "jsonFieldDiffs:",
    diffObject(leftJson, rightJson).join("\n") || "(none)"
  ].join("\n");
}
