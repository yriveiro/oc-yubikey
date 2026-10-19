import { describe, expect, test } from "bun:test"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"

const ROOT = path.resolve(import.meta.dir, "..")
const PRAGMA = "/** @jsxImportSource @opentui/solid */"
const SKIP = new Set(["node_modules", "dist", "build", "coverage"])
const JSX = /<\/[A-Za-z]|<\s*[A-Za-z][\w.$-]*(\s[^<>]*?)?\/?>/
const RELATIVE_IMPORT = /(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || SKIP.has(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full, out)
    else if (entry.name.endsWith(".tsx")) out.push(full)
  }
  return out
}

function relativeImports(file: string): string[] {
  return [...readFileSync(file, "utf8").matchAll(RELATIVE_IMPORT)].map((match) => match[1]!)
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

  // Bun's `.js` -> `.ts` extension fallback loads the target file in a way that
  // bypasses OpenCode's runtime-module rewriting, so a relative specifier that
  // only exists as `.ts` must be written exactly. Otherwise the target's bare
  // imports (for example "@opencode/plugin/rpc") resolve natively and the
  // plugin fails to load with "Cannot find package '@opencode/plugin'".
  test("relative imports across the TUI graph point at files that exist", () => {
    const visited = new Set<string>()
    const queue = [path.join(ROOT, "src", "tui.tsx")]
    const missing: string[] = []
    let checked = 0
    while (queue.length > 0) {
      const file = queue.pop()
      if (!file || visited.has(file)) continue
      visited.add(file)
      for (const specifier of relativeImports(file)) {
        const target = path.resolve(path.dirname(file), specifier)
        checked += 1
        if (!existsSync(target)) missing.push(`${file} -> ${specifier}`)
        else if (/\.tsx?$/.test(target)) queue.push(target)
      }
    }
    expect(checked).toBeGreaterThan(0)
    expect(missing).toEqual([])
  })

  // The JSX runtime import the compiler inserts for the pragma cannot be
  // rewritten by OpenCode's runtime-module plugin when the file lives under
  // node_modules, so `@opentui/solid` must be installed beside the plugin.
  // Optional peers are never installed, which is how the plugin failed with
  // "Cannot find package '@opentui/solid'". Keep the OpenTUI peers required.
  test("OpenTUI peers stay required while the plugin renders JSX", () => {
    const renders = files.some((file) => JSX.test(readFileSync(file, "utf8")))
    if (!renders) return
    const manifest = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
      peerDependencies?: Record<string, string>
      peerDependenciesMeta?: Record<string, { optional?: boolean }>
    }
    for (const peer of ["@opentui/core", "@opentui/solid", "solid-js"]) {
      expect(manifest.peerDependencies?.[peer]).toBeDefined()
      expect(manifest.peerDependenciesMeta?.[peer]?.optional).not.toBe(true)
    }
  })
})
