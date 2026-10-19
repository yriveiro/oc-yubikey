import { describe, expect, test } from "bun:test"
import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"

const ROOT = path.resolve(import.meta.dir, "..")
const PRAGMA = "/** @jsxImportSource @opentui/solid */"
const SKIP = new Set(["node_modules", "dist", "build", "coverage"])
const JSX = /<\/[A-Za-z]|<\s*[A-Za-z][\w.$-]*(\s[^<>]*?)?\/?>/

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || SKIP.has(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full, out)
    else if (entry.name.endsWith(".tsx")) out.push(full)
  }
  return out
}

// Installed plugins live under node_modules, where OpenCode's Solid JSX transform
// deliberately does not run. A `.tsx` that renders JSX must therefore opt into the
// OpenTUI Solid runtime per file; without this pragma Bun compiles the JSX with the
// default React runtime and the plugin fails to load with "Cannot find package 'react'".
describe("TUI JSX runtime", () => {
  const files = walk(ROOT)

  test("discovers TUI sources", () => {
    expect(files.length).toBeGreaterThan(0)
  })

  test.each(files.map((file) => [path.relative(ROOT, file), file] as const))(
    "%s opts into @opentui/solid when it renders JSX",
    (_label, file) => {
      const source = readFileSync(file, "utf8")
      if (!JSX.test(source)) return
      expect(source.startsWith(PRAGMA)).toBe(true)
      expect(/from\s+["']react/.test(source)).toBe(false)
    },
  )
})
