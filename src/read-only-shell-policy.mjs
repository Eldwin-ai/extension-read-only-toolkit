export const READ_ONLY_ALLOWED_TOOLS = [
  "Read",
  "Glob",
  "Grep"
];

export const READ_ONLY_DISALLOWED_TOOLS = [
  "Agent",
  "Task",
  "TaskCreate",
  "Write",
  "Edit",
  "NotebookEdit",
  "TodoWrite",
  "ExitPlanMode",
  "EnterWorktree",
  "WebFetch",
  "WebSearch",
  "AskUserQuestion"
];

export const MUTATING_SHELL_TOKENS = [
  /\bapply\b/i,
  /\bcreate\b/i,
  /\bdelete\b/i,
  /\bdestroy\b/i,
  /\bedit\b/i,
  /\binstall\b/i,
  /\bpatch\b/i,
  /\bpush\b/i,
  /\breplace\b/i,
  /\brestart\b/i,
  /\brollout\s+(restart|undo)\b/i,
  /\brm\b/i,
  /\bscale\b/i,
  /\bset\b/i,
  /\bstart\b/i,
  /\bstop\b/i,
  /\btaint\b/i,
  /\buntaint\b/i,
  /\bupgrade\b/i,
  /\bwrite\b/i,
  /\bchmod\b/i,
  /\bchown\b/i,
  /\bmv\b/i,
  /\bcp\b/i,
  /\bmkdir\b/i,
  /\btouch\b/i,
  /\btee\b/i,
  /\bcurl\b.*\|\s*(sh|bash)\b/i,
  /\bwget\b.*\|\s*(sh|bash)\b/i,
  /(^|[^<])>(?!\s*&\d)/,
  />>/,
  /\|\s*(xargs\s+)?(sh|bash|kubectl\s+apply|terraform\s+apply|helm\s+upgrade|rm|tee)\b/i,
  /(^|[^&|]);\s*/,
  /&&|\|\|/,
  /`|\$\(/,
  /\b--write\b/i,
  /\b--force\b/i,
  /\b--yes\b|\b-y\b/i
];

export const READ_ONLY_COMMAND_PATTERNS = [
  /^\s*pwd\s*$/,
  /^\s*ls(\s|$)/,
  /^\s*find\s+/,
  /^\s*(rg|grep)\s+/,
  /^\s*(cat|head|tail|sed|awk|wc)\s+/,
  /^\s*hostname(\s|$)/,
  /^\s*command\s+-v\s+/,
  /^\s*klist(\s|$)/,
  /^\s*git\s+(status|diff|log|show|branch|remote|rev-parse|describe|ls-files)(\s|$)/,
  /^\s*kubectl\s+(get|describe|logs|top|api-resources|api-versions|explain|version|cluster-info|config\s+(current-context|get-contexts|view))(\s|$)/,
  /^\s*kcsb\s+(get|describe|logs|top|api-resources|api-versions|explain|version|cluster-info|config\s+(current-context|get-contexts|view))(\s|$)/,
  /^\s*kinit\s+-kt\s+\/[A-Za-z0-9._/-]+\s+[A-Za-z0-9_.@/-]+(\s|$)/,
  /^\s*yarn\s+application\s+-status\s+application_[0-9]+_[0-9]+(\s|$)/,
  /^\s*yarn\s+logs\s+-applicationId\s+application_[0-9]+_[0-9]+(\s|$)/,
  /^\s*yarn\s+node\s+-status\s+(?!-)[A-Za-z0-9._:@%-]+:45454(\s|$)/,
  /^\s*hdfs\s+crypto\s+-listZones(\s|$)/,
  /^\s*hdfs\s+dfs\s+-(ls|du|find|cat|tail|test|count|stat)\s+/,
  /^\s*hdfs\s+dfsadmin\s+-report(\s|$)/,
  /^\s*hadoop\s+fs\s+-(ls|cat|head|du|count|stat|test|text)(\s|$)/,
  /^\s*helm\s+(list|status|history|get|version|repo\s+list)(\s|$)/,
  /^\s*aws\s+(?:--profile\s+\S+\s+)?(?:--region\s+\S+\s+)?sts\s+get-caller-identity(\s|$)/,
  /^\s*aws\s+(?:--profile\s+\S+\s+)?(?:--region\s+\S+\s+)?[a-z0-9-]+\s+(describe|list|get|head)-[a-z0-9-]+(\s|$)/,
  /^\s*aws\s+(?:--profile\s+\S+\s+)?(?:--region\s+\S+\s+)?s3\s+ls(\s|$)/,
  /^\s*gcloud\s+(?:--project=\S+\s+)?(?:--account=\S+\s+)?auth\s+list(\s|$)/,
  /^\s*gcloud\s+(?:--project=\S+\s+)?(?:--account=\S+\s+)?config\s+list(\s|$)/,
  /^\s*gcloud\s+(?:--project=\S+\s+)?(?:--account=\S+\s+)?projects\s+(describe|get-iam-policy)(\s|$)/,
  /^\s*gcloud\s+(?:--project=\S+\s+)?(?:--account=\S+\s+)?[a-z0-9-]+(?:\s+[a-z0-9-]+)*\s+(list|describe|read)(\s|$)/,
  /^\s*gcloud\s+storage\s+(buckets|objects)\s+list(\s|$)/,
  /^\s*terraform\s+(version|show|state\s+list|state\s+show|providers|workspace\s+show|output)(\s|$)/,
  /^\s*docker\s+(ps|images|logs|inspect|stats|version|info)(\s|$)/,
  /^\s*(df|du|free|uptime|uname|whoami|id|date|env|printenv)(\s|$)/,
  /^\s*journalctl\s+-k\s+--since\s+/,
  /^\s*(systemctl|journalctl)\s+(status|-u|--unit)(\s|$)/
];

export class ReadOnlyShellPolicy {
  constructor(config = {}) {
    this.config = config;
  }

  validate(command) {
    const normalized = String(command ?? "").trim();

    if (!normalized) {
      return { allowed: false, reason: "empty shell command" };
    }
    if (normalized.includes("\n") || normalized.includes("\r")) {
      return { allowed: false, reason: "multi-line shell commands are not allowed" };
    }

    const mutatingToken = MUTATING_SHELL_TOKENS.find((token) => token.test(normalized));
    if (mutatingToken) {
      return {
        allowed: false,
        reason: `shell command contains mutating or high-risk syntax: ${mutatingToken.source}`
      };
    }

    if (this.readOnlyPatterns().some((pattern) => pattern.test(normalized))) {
      return { allowed: true, reason: "matches read-only command allowlist" };
    }

    return { allowed: false, reason: "command is not in the read-only allowlist" };
  }

  readOnlyPatterns() {
    return [
      ...READ_ONLY_COMMAND_PATTERNS,
      ...(this.config.extraReadOnlyCommandPatterns ?? [])
    ];
  }
}

export class ReadOnlyPolicyDescription {
  text() {
    return [
      "Read-only DevOps policy:",
      `- Auto-approved tools: ${READ_ONLY_ALLOWED_TOOLS.join(", ")}`,
      `- Always denied tools: ${READ_ONLY_DISALLOWED_TOOLS.join(", ")}`,
      "- Bash: denied by default; only explicit read-only command patterns are allowed.",
      "- Filesystem sandbox: enabled with denyWrite on all paths.",
      "- Permission mode: dontAsk, so unapproved tools fail closed."
    ].join("\n");
  }
}

export function isReadOnlyShellCommand(command, config = {}) {
  return new ReadOnlyShellPolicy(config).validate(command);
}

export function describeReadOnlyPolicy() {
  return new ReadOnlyPolicyDescription().text();
}
