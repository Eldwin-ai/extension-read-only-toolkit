import { describe, expect, it } from "vitest";
import {
  assertNonHtmlApiResponse,
  defineReadOnlyTool,
  fail,
  ok
} from "../src/devops-diagnostics.mjs";

describe("devops-diagnostics", () => {
  it("wraps tools with read-only annotations", () => {
    const tool = defineReadOnlyTool({
      name: "example_read",
      description: "Example",
      inputSchema: { type: "object" },
      handler: async () => ok("done")
    });
    expect(tool.annotations?.readOnlyHint).toBe(true);
    expect(tool.annotations?.destructiveHint).toBe(false);
  });

  it("formats ok and fail responses", () => {
    expect(ok("hello").content[0]).toEqual({ type: "text", text: "hello" });
    expect(fail(new Error("nope")).isError).toBe(true);
    expect(fail("nope").content[0].text).toBe("nope");
  });

  it("rejects HTML login pages from API responses", () => {
    expect(() => assertNonHtmlApiResponse("Jira", "<html><form>login</form></html>")).toThrow(
      /HTML login/
    );
    expect(() => assertNonHtmlApiResponse("Jira", '{"ok":true}')).not.toThrow();
  });
});
