# @eldwin-ai/extension-read-only-toolkit

Library extension — shared read-only tool helpers for Eldwin domain extensions and products. Not loaded as MCP tools; imported by sibling extensions.

Upstream: [Eldwin#23](https://github.com/Eldwin-ai/Eldwin/issues/23)

## Exports

| Subpath | Module |
|---------|--------|
| `devops-diagnostics` | `defineReadOnlyTool`, `ok`, `fail`, `assertNonHtmlApiResponse`, log/HTTP diagnostics |
| `enterprise-api-read` | `EnterpriseApiReadService`, URL helpers, Keychain token reads |
| `read-only-command-pack` | Re-exports from `read-only-plan` |
| `read-only-plan` | `ReadOnlyStep`, `shellQuote`, remote command helpers |
| `read-only-shell-policy` | Read-only shell command policy |
| `devops-data-paths` | DevOps data path helpers |

## Usage

```js
import { defineReadOnlyTool, ok, fail } from "@eldwin-ai/extension-read-only-toolkit/devops-diagnostics";
import { EnterpriseApiReadService } from "@eldwin-ai/extension-read-only-toolkit/enterprise-api-read";
```

Install from npm:

```bash
npm install @eldwin-ai/extension-read-only-toolkit
```
