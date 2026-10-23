import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export interface ProcessResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

const environmentAllowlist = [
  "PATH",
  "HOME",
  "USER",
  "TMPDIR",
  "DOCKER_HOST",
  "DOCKER_CONTEXT",
  "XDG_CONFIG_HOME",
  "XDG_CACHE_HOME",
];

export function allowedHostEnvironment(
  additions: Record<string, string> = {},
): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  for (const key of environmentAllowlist) {
    if (process.env[key]) clean[key] = process.env[key];
  }
  return { ...clean, ...additions };
}

export async function runCommand(
  command: string,
  args: string[],
  options: {
    cwd: string;
    timeoutMs: number;
    env?: NodeJS.ProcessEnv;
  },
): Promise<ProcessResult> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? allowedHostEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
      stderr += chunk;
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === "win32") child.kill("SIGKILL");
      else if (child.pid) process.kill(-child.pid, "SIGKILL");
    }, options.timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (exitCode) => {
      clearTimeout(timer);
      resolve({
        exitCode,
        stdout,
        stderr,
        timedOut,
        durationMs: Date.now() - started,
      });
    });
  });
}

export async function runComposeTool(options: {
  composeFile: string;
  service: "trivy" | "semgrep";
  repoPath: string;
  rawDirectory: string;
  args: string[];
  timeoutMs: number;
}): Promise<ProcessResult> {
  await mkdir(options.rawDirectory, { recursive: true, mode: 0o700 });
  const scannerCache = path.join(os.homedir(), ".cache", "security-scan", "tool-cache");
  await mkdir(path.join(scannerCache, "trivy"), { recursive: true, mode: 0o700 });
  const rulesDirectory = path.resolve(path.dirname(options.composeFile), "../rules/semgrep");
  return runCommand(
    "docker",
    [
      "compose",
      "-f",
      options.composeFile,
      "run",
      "--rm",
      "--no-deps",
      options.service,
      ...options.args,
    ],
    {
      cwd: options.repoPath,
      timeoutMs: options.timeoutMs,
      env: allowedHostEnvironment({
        SECURITY_SCAN_REPO: options.repoPath,
        SECURITY_SCAN_OUTPUT: options.rawDirectory,
        SECURITY_SCAN_RULES: rulesDirectory,
        SECURITY_SCAN_CACHE: scannerCache,
        SECURITY_SCAN_UID: String(process.getuid?.() ?? 1000),
        SECURITY_SCAN_GID: String(process.getgid?.() ?? 1000),
      }),
    },
  );
}

export async function persistProcessLog(
  rawDirectory: string,
  toolId: string,
  result: ProcessResult,
): Promise<string> {
  const logPath = path.join(rawDirectory, `${safeName(toolId)}.log`);
  await writeFile(
    logPath,
    `exitCode=${String(result.exitCode)}\ntimedOut=${String(result.timedOut)}\n\nSTDOUT\n${result.stdout}\n\nSTDERR\n${result.stderr}`,
    { mode: 0o600 },
  );
  return logPath;
}

function safeName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_");
}
