import { join } from 'node:path';

/** A location selector only; never a grant of review or signing authority. */
export function validateReviewSnapshotId(value) {
  // The negative lookahead requires the actual end, unlike $ before a final newline.
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,31}(?![\s\S])/.test(value)) {
    const error = new TypeError('REVIEW_SNAPSHOT_ID_INVALID');
    error.code = 'REVIEW_SNAPSHOT_ID_INVALID';
    throw error;
  }
  return value;
}

export function reviewSnapshotDirectory(caseDirectory, snapshotId) {
  return join(caseDirectory, 'review-snapshots', validateReviewSnapshotId(snapshotId));
}
