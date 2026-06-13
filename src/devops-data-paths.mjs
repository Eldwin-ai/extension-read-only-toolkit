import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { parse as parseYaml } from "yaml";

export class PathText {
  static normalize(value) {
    return typeof value === "string" ? value.trim() : "";
  }

  static resolve(path, cwd = process.cwd()) {
    const normalized = PathText.normalize(path);
    if (!normalized) {
      return "";
    }
    return isAbsolute(normalized) ? normalized : resolve(cwd, normalized);
  }
}

export class EnvTokenExpander {
  constructor(env = process.env) {
    this.env = env;
  }

  expand(value) {
    if (typeof value !== "string") {
      return "";
    }
    return value.replace(
      /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g,
      (_match, name, fallback = "") => this.env[name] ?? fallback,
    );
  }
}

export class DevopsDataConfigLoader {
  constructor(env = process.env) {
    this.env = env;
  }

  configPath() {
    return PathText.resolve(this.env.DEVOPS_DATA_CONFIG ?? "config/devops-data.yaml");
  }

  load() {
    const path = this.configPath();
    if (!existsSync(path)) {
      return {};
    }

    const parsed = parseYaml(readFileSync(path, "utf8")) ?? {};
    return parsed.spec?.groups
      ? { dataRoot: parsed.spec.dataRoot, ...parsed.spec.groups }
      : parsed;
  }
}

export class DevopsDataLayout {
  constructor(config = {}, env = process.env) {
    this.config = config;
    this.env = env;
    this.expander = new EnvTokenExpander(env);
  }

  dataRoot() {
    return PathText.resolve(
      this.env.DEVOPS_DATA_ROOT ??
        (this.env.DEVOPS_HOME ? `${this.env.DEVOPS_HOME}/data` : undefined) ??
        (this.expander.expand(this.config.dataRoot) || undefined) ??
        `${homedir()}/.devops-tool/data`,
    );
  }

  value(path) {
    return path.split(".").reduce((current, segment) => {
      if (!current || typeof current !== "object") {
        return undefined;
      }
      return current[segment];
    }, this.config);
  }

  configuredPath(configKey, fallback) {
    const configured = this.expander.expand(this.value(configKey));
    if (!configured) {
      return fallback;
    }
    return isAbsolute(configured) ? configured : resolve(this.dataRoot(), configured);
  }
}

export class DevopsDataPathResolver {
  constructor(env = process.env, config = new DevopsDataConfigLoader(env).load()) {
    this.env = env;
    this.layout = new DevopsDataLayout(config, env);
  }

  root() {
    return this.layout.dataRoot();
  }

  dataPath(...segments) {
    return resolve(this.root(), ...segments);
  }

  cachePath(...segments) {
    return this.dataPath("cache", ...segments);
  }

  projectPath(...segments) {
    return this.dataPath("project", ...segments);
  }

  runtimePath(...segments) {
    return this.dataPath("runtime", ...segments);
  }

  configuredDataPath(envName, configKey, fallback) {
    const envPath = PathText.resolve(this.env[envName]);
    if (envPath) {
      return envPath;
    }
    return this.layout.configuredPath(configKey, fallback);
  }

  codexSessionRoot() {
    return this.configuredDataPath(
      "DEVOPS_CODEX_SESSION_ROOT",
      "project.sessions",
      this.projectPath("sessions", "codex"),
    );
  }

  codexMemoryRoot() {
    return this.configuredDataPath(
      "DEVOPS_CODEX_MEMORY_ROOT",
      "project.codexMemory",
      this.projectPath("memory", "codex"),
    );
  }

  generatedOutputRoot() {
    return this.configuredDataPath(
      "DEVOPS_GENERATED_ROOT",
      "project.generated",
      this.projectPath("generated"),
    );
  }

  tempDataRoot() {
    return this.configuredDataPath("DEVOPS_TMP_ROOT", "tmp", this.dataPath("tmp"));
  }

  summary() {
    return {
      dataRoot: this.root(),
      runtime: {
        claude: this.runtimePath("claude"),
        npm: this.runtimePath("npm"),
        cache: this.runtimePath("cache"),
        config: this.runtimePath("config"),
      },
      project: {
        agentMemory: this.projectPath("agent-memory-local"),
        memory: this.projectPath("memory"),
        codexMemory: this.codexMemoryRoot(),
        sessions: this.codexSessionRoot(),
        generated: this.generatedOutputRoot(),
      },
      cache: {},
      tmp: this.tempDataRoot(),
    };
  }
}

function resolver(env = process.env) {
  return new DevopsDataPathResolver(env);
}

export function devopsDataRoot(env = process.env) {
  return resolver(env).root();
}

export function devopsDataPath(...segments) {
  return resolver().dataPath(...segments);
}

export function devopsCachePath(...segments) {
  return resolver().cachePath(...segments);
}

export function devopsProjectDataPath(...segments) {
  return resolver().projectPath(...segments);
}

export function devopsRuntimeDataPath(...segments) {
  return resolver().runtimePath(...segments);
}

export function configuredDataPath(envName, configKey, fallback) {
  return resolver().configuredDataPath(envName, configKey, fallback);
}

export function codexSessionRoot() {
  return resolver().codexSessionRoot();
}

export function codexMemoryRoot() {
  return resolver().codexMemoryRoot();
}

export function generatedOutputRoot() {
  return resolver().generatedOutputRoot();
}

export function tempDataRoot() {
  return resolver().tempDataRoot();
}

export function dataPathSummary() {
  return resolver().summary();
}
