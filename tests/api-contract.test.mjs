import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

test("API Contract - Frontend calls match registered backend endpoints", () => {
  const feEndpoints = new Set();
  const feDynamicEndpoints = new Set();

  function scanDir(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        scanDir(full);
      } else if (ent.name.endsWith(".ts") || ent.name.endsWith(".tsx")) {
        const content = fs.readFileSync(full, "utf8");
        // Match concatenated api('/api/...' + ...)
        for (const m of content.matchAll(/api\(['"](\/api\/[^'"`?]+)['"]\s*\+/g)) {
          feDynamicEndpoints.add(m[1] + ":param");
        }
        // Match static api('/api/...') without trailing '+'
        for (const m of content.matchAll(/api\(['"](\/api\/[^'"`?]+)['"](?!\s*\+)/g)) {
          feEndpoints.add(m[1]);
        }
        // Match dynamic template literal api(`/api/.../${...}`)
        for (const m of content.matchAll(/api\(`(\/api\/[^`?]+)`/g)) {
          const raw = m[1];
          // Convert template expressions to :param
          const normalized = raw.replace(/\$\{[^}]+\}/g, ":param");
          if (normalized.includes(":param")) {
            feDynamicEndpoints.add(normalized);
          } else {
            feEndpoints.add(normalized);
          }
        }
      }
    }
  }

  scanDir(path.join(ROOT, "src"));

  const beServerPath = path.join(ROOT, "backend", "server.production.ts");
  const beContent = fs.readFileSync(beServerPath, "utf8");

  const beEndpoints = new Set();
  for (const m of beContent.matchAll(/(?:app\.(?:get|post|put|delete|patch)|get|post|del)\(['"](\/api\/[^'"]+)['"]/g)) {
    beEndpoints.add(m[1]);
  }

  // Verify all static frontend endpoints exist in backend
  for (const ep of feEndpoints) {
    assert.ok(
      beEndpoints.has(ep),
      `Frontend static API call ${ep} is missing in backend server.production.ts`
    );
  }

  // Verify dynamic frontend endpoints map to parameterized routes
  for (const dep of feDynamicEndpoints) {
    const regexPattern = "^" + dep.replace(/:param/g, "[^/]+") + "$";
    const reg = new RegExp(regexPattern);
    const matched = Array.from(beEndpoints).some((beRoute) => {
      const beRegex = "^" + beRoute.replace(/:[a-zA-Z_]+/g, "[^/]+") + "$";
      return new RegExp(beRegex).test(dep.replace(/:param/g, "test-id"));
    });
    assert.ok(
      matched,
      `Frontend dynamic API call ${dep} has no matching parameterized route in backend`
    );
  }

  // Explicit check for P1-03 /api/status and /api/network/check-port
  assert.ok(beEndpoints.has("/api/status"), "/api/status route must be registered");
  assert.ok(beEndpoints.has("/api/network/check-port"), "/api/network/check-port route must be registered");
});
