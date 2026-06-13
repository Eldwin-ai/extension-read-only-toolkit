export type ReadOnlyValidation = {
  allowed: boolean;
  reason: string;
};

export type ReadOnlyPolicyConfig = {
  extraReadOnlyCommandPatterns?: RegExp[];
};

export const READ_ONLY_ALLOWED_TOOLS: readonly string[];
export const READ_ONLY_DISALLOWED_TOOLS: readonly string[];
export const MUTATING_SHELL_TOKENS: RegExp[];
export const READ_ONLY_COMMAND_PATTERNS: RegExp[];

export class ReadOnlyShellPolicy {
  constructor(config?: ReadOnlyPolicyConfig);
  validate(command: string): ReadOnlyValidation;
  readOnlyPatterns(): RegExp[];
}

export class ReadOnlyPolicyDescription {
  text(): string;
}

export function isReadOnlyShellCommand(command: string, config?: ReadOnlyPolicyConfig): ReadOnlyValidation;
export function describeReadOnlyPolicy(): string;
