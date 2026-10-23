export class UsageError extends Error {
  readonly exitCode = 3 as const;

  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export function isEnoent(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}
