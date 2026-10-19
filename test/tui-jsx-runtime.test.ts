import { describe, expect, test } from "bun:test"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const SKIP = new Set(["node_modules", "dist", "build", "coverage"])
const JSX_TAG = /<\/[A-Za-z]|<\s*(?:box|text|span|Show|TouchModal|PinentryModal)\b/
const RELATIVE_IMPORT = /(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g

function walkSourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || SKIP.has(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name !== "test") walkSourceFiles(full, out)
    } else if (entry.name.endsWith(".ts") || entry.name.endsWith(".tsx")) {
      out.push(full)
    }
  }
  return out
}

function relativeImports(file: string): string[] {
  return [...readFileSync(file, "utf8").matchAll(RELATIVE_IMPORT)].map((match) => match[1]!)
}

describe("TUI runtime & module resolution invariants", () => {
  const files = walkSourceFiles(ROOT)

  test("discovers plugin source files", () => {
    expect(files.length).toBeGreaterThan(0)
  })

  test("TUI sources avoid raw JSX syntax so node_modules loads never inject jsx-dev-runtime", () => {
    const tuiFiles = files.filter((file) => file.endsWith(".tsx"))
    expect(tuiFiles.length).toBeGreaterThan(0)
    for (const file of tuiFiles) {
      const source = readFileSync(file, "utf8")
      expect(JSX_TAG.test(source)).toBe(false)
      expect(/from\s+["']react/.test(source)).toBe(false)
    }
  })

  test("relative imports across all plugin entrypoints point at files that exist on disk", () => {
    const missing: string[] = []
    let checked = 0
    for (const file of files) {
      for (const specifier of relativeImports(file)) {
        const target = path.resolve(path.dirname(file), specifier)
        checked += 1
        if (!existsSync(target)) {
          missing.push(`${path.relative(ROOT, file)} -> ${specifier}`)
        }
      }
    }
    expect(checked).toBeGreaterThan(0)
    expect(missing).toEqual([])
  })

  test("host peerDependencies are marked optional so npm does not install duplicate runtime trees", () => {
    const manifest = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8")) as {
      peerDependencies?: Record<string, string>
      peerDependenciesMeta?: Record<string, { optional?: boolean }>
    }
    for (const peer of [
      "@opencode/plugin",
      "@opencode/theme",
      "@opentui/core",
      "@opentui/solid",
      "solid-js",
    ]) {
      expect(manifest.peerDependencies?.[peer]).toBeDefined()
      expect(manifest.peerDependenciesMeta?.[peer]?.optional).toBe(true)
    }
  })
})
