import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import type { SecurityScanConfig } from "./config.js";
import { UsageError, isEnoent } from "./errors.js";
import type { ComponentProfile, RepositoryProfile } from "./types.js";

const ignoredDirectories = new Set([
  ".git",
  ".next",
  ".venv",
  "node_modules",
  "dist",
  "build",
  "coverage",
  "security-reports",
]);

export async function assertRepositoryPath(input: string): Promise<string> {
  try {
    const canonical = await realpath(path.resolve(input));
    const stat = await lstat(canonical);
    if (!stat.isDirectory()) {
      throw new UsageError(`Repository path is not a directory: ${input}`);
    }
    return canonical;
  } catch (error) {
    if (error instanceof UsageError) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw new UsageError(`Repository path is not usable: ${message}`);
  }
}

export async function assertPathInsideRepository(
  repoPath: string,
  candidate: string,
): Promise<string> {
  const repo = await realpath(repoPath);
  const resolvedInput = path.resolve(repoPath, candidate);
  const fromInputRepo = path.relative(path.resolve(repoPath), resolvedInput);
  if (fromInputRepo.startsWith("..") || path.isAbsolute(fromInputRepo)) {
    throw new UsageError("Path must remain inside the target repository");
  }
  const resolved = fromInputRepo === "" ? repo : path.resolve(repo, fromInputRepo);
  const segments = fromInputRepo === "" ? [] : fromInputRepo.split(path.sep);
  let cursor = repo;
  for (const segment of segments) {
    cursor = path.join(cursor, segment);
    try {
      const stat = await lstat(cursor);
      if (!stat.isSymbolicLink()) continue;
      let target: string;
      try {
        target = await realpath(cursor);
      } catch (error) {
        if (error instanceof UsageError) throw error;
        throw new UsageError("Path follows a symlink whose target cannot be resolved");
      }
      const targetRelative = path.relative(repo, target);
      if (targetRelative.startsWith("..") || path.isAbsolute(targetRelative)) {
        throw new UsageError("Path follows a symlink outside the target repository");
      }
    } catch (error) {
      if (error instanceof UsageError) throw error;
      if (isEnoent(error)) break;
      throw error;
    }
  }
  return fromInputRepo === "" ? repo : resolved;
}

export async function assertNoEscapingSymlinks(repoPath: string): Promise<void> {
  const repo = await realpath(repoPath);
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        let target: string;
        try {
          target = await realpath(absolute);
        } catch (error) {
          if (error instanceof UsageError) throw error;
          throw new UsageError(
            `Refusing to scan because a symlink target cannot be resolved: ${path.relative(repo, absolute)}`,
          );
        }
        const relative = path.relative(repo, target);
        if (relative.startsWith("..") || path.isAbsolute(relative)) {
          throw new UsageError(
            `Refusing to scan because a symlink escapes the repository: ${path.relative(repo, absolute)}`,
          );
        }
        continue;
      }
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(absolute);
      }
    }
  }
  await visit(repo);
}

export async function profileRepository(
  repoPath: string,
  config: SecurityScanConfig,
  now = new Date(),
): Promise<RepositoryProfile> {
  const files = await walkFiles(repoPath);
  const componentPaths =
    config.components.length > 0
      ? config.components.map((entry) => entry.path)
      : detectComponentPaths(files);
  const components = await Promise.all(
    componentPaths.map((componentPath) =>
      buildComponent(repoPath, componentPath, componentPaths, files),
    ),
  );

  return {
    repositoryPath: repoPath,
    generatedAt: now.toISOString(),
    components,
    dockerfiles: files.filter((file) => /(^|\/)Dockerfile[^/]*$/.test(file)),
    composeFiles: files.filter((file) =>
      /(^|\/)((docker-compose|compose)(\.[^.]+)?|[^/]+\.compose)\.ya?ml$/.test(file),
    ),
    ciFiles: files.filter((file) => /^\.github\/workflows\/.+\.ya?ml$/.test(file)),
    previousReports: files.filter((file) =>
      /^security-reports\/[^/]+\/scan-manifest\.json$/.test(file),
    ),
  };
}

async function walkFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    await Promise.all(
      entries.map(async (entry) => {
        if (entry.isSymbolicLink()) return;
        const absolute = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          if (directory === root && entry.name === "security-reports") {
            await collectReportManifests(root, absolute, files);
            return;
          }
          if (!ignoredDirectories.has(entry.name)) await visit(absolute);
          return;
        }
        if (entry.isFile()) files.push(path.relative(root, absolute).split(path.sep).join("/"));
      }),
    );
  }
  await visit(root);
  return files.sort();
}

async function collectReportManifests(
  root: string,
  directory: string,
  files: string[],
): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await collectReportManifests(root, absolute, files);
      continue;
    }
    if (entry.isFile() && entry.name === "scan-manifest.json") {
      files.push(path.relative(root, absolute).split(path.sep).join("/"));
    }
  }
}

function detectComponentPaths(files: string[]): string[] {
  const manifests = new Set(["package.json", "pyproject.toml", "pubspec.yaml", "go.mod", "Cargo.toml"]);
  const paths = new Set<string>();
  for (const file of files) {
    if (manifests.has(path.posix.basename(file))) {
      paths.add(path.posix.dirname(file) === "." ? "." : path.posix.dirname(file));
    }
  }
  return paths.size > 0 ? [...paths].sort() : ["."];
}

async function buildComponent(
  root: string,
  componentPath: string,
  allComponentPaths: string[],
  files: string[],
): Promise<ComponentProfile> {
  const normalized = componentPath === "." ? "." : componentPath.replace(/\\/g, "/").replace(/\/$/, "");
  const childRoots =
    normalized === "."
      ? allComponentPaths.filter((candidate) => candidate !== ".").map((candidate) => `${candidate}/`)
      : [];
  const scoped = files.filter((file) => {
    if (normalized !== "." && file !== normalized && !file.startsWith(`${normalized}/`)) {
      return false;
    }
    return !childRoots.some((childRoot) => file.startsWith(childRoot));
  });
  const relative = (name: string) => (normalized === "." ? name : `${normalized}/${name}`);
  const manifests = [
    "package.json",
    "pyproject.toml",
    "pubspec.yaml",
    "go.mod",
    "Cargo.toml",
  ].filter((name) => scoped.includes(relative(name)));
  const lockfiles = [
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "requirements.txt",
    "pubspec.lock",
    "go.sum",
    "Cargo.lock",
  ].filter((name) => scoped.includes(relative(name)));
  const languages = detectLanguages(scoped);
  const frameworks = await detectFrameworks(root, normalized, manifests);
  return {
    id: normalized === "." ? "root" : normalized.replace(/[^a-zA-Z0-9_-]+/g, "-"),
    path: normalized,
    languages,
    frameworks,
    lockfiles,
    manifests,
    hasExistingDartWorkspace:
      manifests.includes("pubspec.yaml") &&
      scoped.includes(relative(".dart_tool/package_config.json")),
  };
}

function detectLanguages(files: string[]): string[] {
  const extensions: Record<string, string> = {
    ".dart": "dart",
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
  };
  return [...new Set(files.map((file) => extensions[path.posix.extname(file)]).filter(Boolean))].sort() as string[];
}

async function detectFrameworks(
  root: string,
  componentPath: string,
  manifests: string[],
): Promise<string[]> {
  const frameworks = new Set<string>();
  if (manifests.includes("package.json")) {
    const packagePath = path.join(root, componentPath, "package.json");
    const raw = JSON.parse(await readFile(packagePath, "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...raw.dependencies, ...raw.devDependencies };
    if (deps.next) frameworks.add("nextjs");
    if (deps["@nestjs/core"]) frameworks.add("nestjs");
    if (deps.react) frameworks.add("react");
    if (deps.express) frameworks.add("express");
  }
  if (manifests.includes("pyproject.toml")) {
    const text = await readFile(path.join(root, componentPath, "pyproject.toml"), "utf8");
    if (/\bfastapi\b/i.test(text)) frameworks.add("fastapi");
    if (/\bdjango\b/i.test(text)) frameworks.add("django");
  }
  if (manifests.includes("pubspec.yaml")) {
    const text = await readFile(path.join(root, componentPath, "pubspec.yaml"), "utf8");
    if (/^\s*flutter:\s*$/m.test(text) || /^\s*sdk:\s*flutter\s*$/m.test(text)) {
      frameworks.add("flutter");
    } else {
      frameworks.add("dart");
    }
  }
  return [...frameworks].sort();
}
