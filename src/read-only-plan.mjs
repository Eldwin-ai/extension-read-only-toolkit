export function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

export function remoteCommandInput({ host, command, timeoutMs = 60_000 }) {
  return {
    targetType: "ssh",
    host,
    command,
    timeoutMs
  };
}

export class ReadOnlyStep {
  constructor({ id, purpose, command, expectedEvidence }) {
    this.id = id;
    this.purpose = purpose;
    this.command = command;
    this.expectedEvidence = expectedEvidence;
  }

  toMarkdown() {
    return [
      `### ${this.id}`,
      `Purpose: ${this.purpose}`,
      "",
      "```bash",
      this.command,
      "```",
      "",
      `Evidence to capture: ${this.expectedEvidence}`
    ].join("\n");
  }

  toJson() {
    return {
      id: this.id,
      purpose: this.purpose,
      command: this.command,
      expectedEvidence: this.expectedEvidence
    };
  }
}

export class ReadOnlyCommand extends ReadOnlyStep {}
