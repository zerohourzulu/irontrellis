import { dirname } from "node:path";
import {
  openSync,
  closeSync,
  fstatSync,
  writeSync,
  fsyncSync,
  constants,
} from "node:fs";

/** One trusted broker writer; protected parent directory, no agent write access. */
export function policyJournal(file) {
  return (evidence) => {
    const line = Buffer.from(JSON.stringify(evidence) + "\n");
    if (line.length > 32768) throw Error("POLICY_EVIDENCE_TOO_LARGE");
    const fd = openSync(
      file,
      constants.O_WRONLY |
        constants.O_APPEND |
        constants.O_CREAT |
        constants.O_NOFOLLOW |
        constants.O_NONBLOCK,
      0o600,
    );
    try {
      const stat = fstatSync(fd);
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        (stat.mode & 0o077) !== 0 ||
        stat.size + line.length > 1048576
      ) {
        throw Error("POLICY_JOURNAL_UNAVAILABLE");
      }
      if (writeSync(fd, line) !== line.length)
        throw Error("POLICY_WRITE_UNCONFIRMED");
      fsyncSync(fd);
      const parent = openSync(
        dirname(file),
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        fsyncSync(parent);
      } finally {
        closeSync(parent);
      }
    } finally {
      closeSync(fd);
    }
  };
}
