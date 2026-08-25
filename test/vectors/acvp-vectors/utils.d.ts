/** Reads a .json or .json.gz file and parses it. Whole-file, synchronous. */
export function jsonGZ(path: string | URL): any;

/**
 * Streams the top-level "testGroups" array of a Wycheproof/ACVP-style file,
 * yielding one group at a time with bounded memory.
 */
export function jsonGZGroups(path: string | URL): AsyncGenerator<any, void, unknown>;
