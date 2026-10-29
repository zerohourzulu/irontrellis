/**
 * Whether a module is the process's entry point (the bins in this package are
 * the compiled modules themselves, which the package index also imports).
 */
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * True when `argv1` (the script Node was started with) is the module at
 * `moduleUrl`. Both sides are resolved through symlinks (npm and pnpm link
 * bins). On Windows, where npm starts the script from a `.cmd` shim, the
 * comparison ignores case: the file system does, and a shim or a shell can
 * spell the drive letter or a directory in another case than the module URL.
 */
export function isEntryPoint(moduleUrl: string, argv1: string | undefined = process.argv[1], platform: NodeJS.Platform = process.platform): boolean {
  if (argv1 === undefined || argv1 === "") return false;
  const real = (path: string): string => { try { return realpathSync(path); } catch { return path; } };
  const script = real(argv1), module = real(fileURLToPath(moduleUrl));
  return platform === "win32" ? script.toLowerCase() === module.toLowerCase() : script === module;
}
