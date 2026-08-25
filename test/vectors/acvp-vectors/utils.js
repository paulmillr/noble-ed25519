// Helpers for consumers of this repository. Dependency-free, Node built-ins
// only. Import directly from the submodule:
//
//   import { jsonGZ } from './vectors/large/utils.js';
//   const vectors = jsonGZ(new URL('./vectors/large/acvp/.../prompt.json.gz', import.meta.url));
//
// Both helpers accept a path string or a file URL, and transparently handle
// uncompressed .json files as well as .json.gz.
import { createReadStream, readFileSync } from 'node:fs';
import { createGunzip, gunzipSync } from 'node:zlib';

const isGz = (path) => String(path).endsWith('.gz');

/** Reads a .json or .json.gz file and parses it. Whole-file, synchronous. */
export function jsonGZ(path) {
  let data = readFileSync(path);
  if (isGz(path)) data = gunzipSync(data);
  return JSON.parse(new TextDecoder().decode(data));
}

function textStream(path) {
  const stream = createReadStream(path);
  if (!isGz(path)) return stream.setEncoding('utf8');
  return stream.pipe(createGunzip()).setEncoding('utf8');
}

/**
 * Streams the top-level "testGroups" array of a Wycheproof/ACVP-style file,
 * yielding one group at a time. Keeps memory bounded for large files: only
 * one decompressed group is held at once, not the whole document.
 */
export async function* jsonGZGroups(path) {
  const key = '"testGroups"';
  let buf = '';
  let inGroups = false;
  let inObject = false;
  let inString = false;
  let escaped = false;
  let depth = 0;
  let obj = '';
  for await (const chunk of textStream(path)) {
    buf += chunk;
    while (buf.length) {
      if (!inGroups) {
        const keyStart = buf.indexOf(key);
        if (keyStart === -1) {
          buf = buf.slice(Math.max(0, buf.length - key.length));
          break;
        }
        const arrayStart = buf.indexOf('[', keyStart + key.length);
        if (arrayStart === -1) {
          buf = buf.slice(keyStart);
          break;
        }
        buf = buf.slice(arrayStart + 1);
        inGroups = true;
      }
      if (!inObject) {
        const next = buf.search(/[^\s,]/);
        if (next === -1) {
          buf = '';
          break;
        }
        buf = buf.slice(next);
        if (buf[0] === ']') return;
        if (buf[0] !== '{') throw new Error(`expected JSON object in ${path}`);
        inObject = true;
        inString = false;
        escaped = false;
        depth = 0;
        obj = '';
      }
      let end = -1;
      for (let i = 0; i < buf.length; i++) {
        const c = buf[i];
        if (inString) {
          if (escaped) escaped = false;
          else if (c === '\\') escaped = true;
          else if (c === '"') inString = false;
          continue;
        }
        if (c === '"') inString = true;
        else if (c === '{') depth++;
        else if (c === '}') {
          depth--;
          if (depth === 0) {
            end = i + 1;
            break;
          }
        }
      }
      if (end === -1) {
        obj += buf;
        buf = '';
        break;
      }
      obj += buf.slice(0, end);
      buf = buf.slice(end);
      inObject = false;
      yield JSON.parse(obj);
    }
  }
  if (inGroups || inObject) throw new Error(`unexpected end of JSON stream in ${path}`);
}
