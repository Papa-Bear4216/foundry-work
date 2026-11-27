/**
 * QR Code Model 2 encoder (ISO/IEC 18004), byte mode only, versions 1 to 40, error correction L, M, Q or H.
 * Pure TypeScript with no dependencies: it prints the chain-head anchor (Architecture 8.1 step 9).
 *
 * The encoder picks the smallest version that holds the data. Without a mask override it picks the mask with the
 * lowest penalty score (the four rules N1 to N4 of the standard); any mask gives a valid symbol, the penalty only
 * makes scanning easier. `mask` pins one of the eight masks, so a test can compare a whole bit matrix with a vector
 * produced by an independent encoder.
 */
import { check } from './bytes.ts';

export type QrErrorCorrection = 'L' | 'M' | 'Q' | 'H';

export interface QrOptions {
  errorCorrection?: QrErrorCorrection;
  /** Lowest version to use (1 to 40). */
  minVersion?: number;
  /** Use this mask (0 to 7) instead of the lowest-penalty mask. */
  mask?: number;
}

export interface QrCode {
  version: number;
  errorCorrection: QrErrorCorrection;
  mask: number;
  size: number;
  /** `modules[y][x]`, true for a dark module. No quiet zone. */
  modules: boolean[][];
}

const LEVELS: readonly QrErrorCorrection[] = ['L', 'M', 'Q', 'H'];
/** The two format bits of each level (the standard's order is M, L, H, Q = 00, 01, 10, 11). */
const FORMAT_BITS: Readonly<Record<QrErrorCorrection, number>> = { L: 1, M: 0, Q: 3, H: 2 };

// Index [level][version]; index 0 is unused.
const ECC_CODEWORDS_PER_BLOCK: readonly (readonly number[])[] = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const ERROR_CORRECTION_BLOCKS: readonly (readonly number[])[] = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

function bit(value: number, index: number): boolean {
  return ((value >>> index) & 1) !== 0;
}

/** Modules left for data and error correction after every function pattern. */
export function qrRawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const alignments = Math.floor(version / 7) + 2;
    result -= (25 * alignments - 10) * alignments - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

/** Data codewords (8-bit) of one version and level. */
export function qrDataCodewords(version: number, level: QrErrorCorrection): number {
  const l = LEVELS.indexOf(level);
  return Math.floor(qrRawDataModules(version) / 8) - ECC_CODEWORDS_PER_BLOCK[l]![version]! * ERROR_CORRECTION_BLOCKS[l]![version]!;
}

/** Error-correction block layout of one version and level (from the standard's tables). */
export function qrBlockLayout(version: number, level: QrErrorCorrection): { blocks: number; eccPerBlock: number } {
  const l = LEVELS.indexOf(level);
  return { blocks: ERROR_CORRECTION_BLOCKS[l]![version]!, eccPerBlock: ECC_CODEWORDS_PER_BLOCK[l]![version]! };
}

/** Bits of the byte-mode character count field. */
function countBits(version: number): number {
  return version <= 9 ? 8 : 16;
}

function gfMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

/** Generator polynomial of the given degree (coefficients from the highest power down, leading 1 dropped). */
export function reedSolomonDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMultiply(result[j]!, root);
      if (j + 1 < result.length) result[j]! ^= result[j + 1]!;
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

export function reedSolomonRemainder(data: readonly number[], divisor: readonly number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0);
  for (const byte of data) {
    const factor = byte ^ result.shift()!;
    result.push(0);
    for (let i = 0; i < divisor.length; i++) result[i]! ^= gfMultiply(divisor[i]!, factor);
  }
  return result;
}

/** Positions of the alignment pattern centres on each axis. */
export function qrAlignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let position = version * 4 + 10; result.length < count; position -= step) result.splice(1, 0, position);
  return result;
}

/** The 15 format bits (level, mask, BCH(15,5) and the 0x5412 mask). */
export function qrFormatBits(level: QrErrorCorrection, mask: number): number {
  const data = (FORMAT_BITS[level] << 3) | mask;
  let remainder = data;
  for (let i = 0; i < 10; i++) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
  return ((data << 10) | remainder) ^ 0x5412;
}

/** The 18 version bits (version 7 and up: version and BCH(18,6)). */
export function qrVersionBits(version: number): number {
  let remainder = version;
  for (let i = 0; i < 12; i++) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
  return (version << 12) | remainder;
}

export function qrMaskApplies(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: throw new RangeError('QR mask must be 0 to 7.');
  }
}

class QrSymbol {
  readonly size: number;
  readonly modules: boolean[][];
  readonly isFunction: boolean[][];
  readonly version: number;

  constructor(version: number) {
    this.version = version;
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.isFunction = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }

  set(x: number, y: number, dark: boolean): void {
    this.modules[y]![x] = dark;
    this.isFunction[y]![x] = true;
  }

  drawFunctionPatterns(): void {
    for (let i = 0; i < this.size; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    this.finder(3, 3);
    this.finder(this.size - 4, 3);
    this.finder(3, this.size - 4);
    const positions = qrAlignmentPositions(this.version);
    const last = positions.length - 1;
    for (let i = 0; i < positions.length; i++) {
      for (let j = 0; j < positions.length; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
        this.alignment(positions[i]!, positions[j]!);
      }
    }
    this.drawFormat(0, 'L'); // placeholder; the real bits are drawn after masking
    this.drawVersion();
  }

  finder(x: number, y: number): void {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = x + dx;
        const yy = y + dy;
        if (xx >= 0 && xx < this.size && yy >= 0 && yy < this.size) this.set(xx, yy, distance !== 2 && distance !== 4);
      }
    }
  }

  alignment(x: number, y: number): void {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) this.set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }

  drawFormat(mask: number, level: QrErrorCorrection): void {
    const bits = qrFormatBits(level, mask);
    for (let i = 0; i <= 5; i++) this.set(8, i, bit(bits, i));
    this.set(8, 7, bit(bits, 6));
    this.set(8, 8, bit(bits, 7));
    this.set(7, 8, bit(bits, 8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(bits, i));
    for (let i = 0; i < 8; i++) this.set(this.size - 1 - i, 8, bit(bits, i));
    for (let i = 8; i < 15; i++) this.set(8, this.size - 15 + i, bit(bits, i));
    this.set(8, this.size - 8, true); // the dark module
  }

  drawVersion(): void {
    if (this.version < 7) return;
    const bits = qrVersionBits(this.version);
    for (let i = 0; i < 18; i++) {
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, bit(bits, i));
      this.set(b, a, bit(bits, i));
    }
  }

  drawCodewords(data: readonly number[]): void {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vertical = 0; vertical < this.size; vertical++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vertical : vertical;
          if (!this.isFunction[y]![x] && i < data.length * 8) {
            this.modules[y]![x] = bit(data[i >>> 3]!, 7 - (i & 7));
            i++;
          }
        }
      }
    }
    check(i === data.length * 8, 'LENGTH');
  }

  applyMask(mask: number): void {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (!this.isFunction[y]![x] && qrMaskApplies(mask, x, y)) this.modules[y]![x] = !this.modules[y]![x];
      }
    }
  }
}

/** Penalty score of a finished symbol: rules N1 (runs), N2 (2x2 blocks), N3 (finder-like) and N4 (balance). */
export function qrPenalty(modules: readonly (readonly boolean[])[]): number {
  const size = modules.length;
  let penalty = 0;
  const line = (get: (i: number) => boolean) => {
    let run = 1;
    for (let i = 1; i <= size; i++) {
      if (i < size && get(i) === get(i - 1)) {
        run++;
      } else {
        if (run >= 5) penalty += 3 + (run - 5);
        run = 1;
      }
    }
    const pattern = [true, false, true, true, true, false, true];
    for (let i = 0; i + 7 <= size; i++) {
      if (!pattern.every((dark, k) => get(i + k) === dark)) continue;
      const lightBefore = i >= 4 && [1, 2, 3, 4].every(k => !get(i - k));
      const lightAfter = i + 11 <= size && [7, 8, 9, 10].every(k => !get(i + k));
      if (lightBefore) penalty += 40;
      if (lightAfter) penalty += 40;
    }
  };
  for (let y = 0; y < size; y++) line(x => modules[y]![x]!);
  for (let x = 0; x < size; x++) line(y => modules[y]![x]!);
  for (let y = 0; y + 1 < size; y++) {
    for (let x = 0; x + 1 < size; x++) {
      const dark = modules[y]![x];
      if (dark === modules[y]![x + 1] && dark === modules[y + 1]![x] && dark === modules[y + 1]![x + 1]) penalty += 3;
    }
  }
  let dark = 0;
  for (const row of modules) for (const module of row) if (module) dark++;
  const total = size * size;
  penalty += Math.floor(Math.abs(dark * 100 - total * 50) / (total * 5)) * 10;
  return penalty;
}

/** Encode bytes as one byte-mode QR symbol. */
export function encodeQr(data: Uint8Array, options: QrOptions = {}): QrCode {
  const level = options.errorCorrection ?? 'M';
  check(LEVELS.includes(level));
  const minVersion = options.minVersion ?? 1;
  check(Number.isSafeInteger(minVersion) && minVersion >= 1 && minVersion <= 40);
  if (options.mask !== undefined) check(Number.isSafeInteger(options.mask) && options.mask >= 0 && options.mask <= 7);
  let version = minVersion;
  for (; ; version++) {
    check(version <= 40, 'LENGTH');
    if (data.length < 2 ** countBits(version) && 4 + countBits(version) + data.length * 8 <= qrDataCodewords(version, level) * 8) break;
  }
  const capacity = qrDataCodewords(version, level) * 8;
  const bits: number[] = [];
  const append = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  append(0b0100, 4);
  append(data.length, countBits(version));
  for (const byte of data) append(byte, 8);
  append(0, Math.min(4, capacity - bits.length));
  append(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) append(pad, 8);
  const codewords: number[] = [];
  for (let i = 0; i < bits.length; i += 8) codewords.push(bits.slice(i, i + 8).reduce((byte, b) => (byte << 1) | b, 0));

  const l = LEVELS.indexOf(level);
  const blockCount = ERROR_CORRECTION_BLOCKS[l]![version]!;
  const eccLength = ECC_CODEWORDS_PER_BLOCK[l]![version]!;
  const raw = Math.floor(qrRawDataModules(version) / 8);
  const shortBlocks = blockCount - (raw % blockCount);
  const shortLength = Math.floor(raw / blockCount);
  const divisor = reedSolomonDivisor(eccLength);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < blockCount; i++) {
    const block = codewords.slice(k, k + shortLength - eccLength + (i < shortBlocks ? 0 : 1));
    k += block.length;
    const ecc = reedSolomonRemainder(block, divisor);
    if (i < shortBlocks) block.push(0);
    blocks.push([...block, ...ecc]);
  }
  const interleaved: number[] = [];
  for (let i = 0; i < blocks[0]!.length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i !== shortLength - eccLength || j >= shortBlocks) interleaved.push(blocks[j]![i]!);
    }
  }
  check(interleaved.length === raw, 'LENGTH');

  const build = (mask: number) => {
    const symbol = new QrSymbol(version);
    symbol.drawFunctionPatterns();
    symbol.drawCodewords(interleaved);
    symbol.applyMask(mask);
    symbol.drawFormat(mask, level);
    return symbol;
  };
  let mask = options.mask;
  if (mask === undefined) {
    let best = Infinity;
    for (let candidate = 0; candidate < 8; candidate++) {
      const score = qrPenalty(build(candidate).modules);
      if (score < best) {
        best = score;
        mask = candidate;
      }
    }
  }
  const symbol = build(mask!);
  return { version, errorCorrection: level, mask: mask!, size: symbol.size, modules: symbol.modules };
}

/**
 * Terminal rendering with UTF-8 half blocks, two module rows per text line, and a quiet zone of `quiet` modules.
 * Dark modules print as ink, which is right on paper and on a light terminal; `invert` swaps the shades for a dark
 * terminal background.
 */
export function renderQrText(code: QrCode, { quiet = 4, invert = false }: { quiet?: number; invert?: boolean } = {}): string {
  const span = code.size + quiet * 2;
  const dark = (x: number, y: number) => {
    const xx = x - quiet;
    const yy = y - quiet;
    const value = xx >= 0 && yy >= 0 && xx < code.size && yy < code.size && code.modules[yy]![xx]!;
    return invert ? !value : value;
  };
  const lines: string[] = [];
  for (let y = 0; y < span; y += 2) {
    let line = '';
    for (let x = 0; x < span; x++) {
      const top = dark(x, y);
      const bottom = y + 1 < span && dark(x, y + 1);
      line += top ? (bottom ? '█' : '▀') : (bottom ? '▄' : ' ');
    }
    lines.push(line);
  }
  return lines.join('\n') + '\n';
}

/** SVG rendering: one path of unit squares, dark on a white background, with a quiet zone. */
export function renderQrSvg(code: QrCode, { quiet = 4, moduleSize = 8 }: { quiet?: number; moduleSize?: number } = {}): string {
  check(Number.isSafeInteger(quiet) && quiet >= 0 && Number.isSafeInteger(moduleSize) && moduleSize >= 1);
  const span = code.size + quiet * 2;
  let path = '';
  for (let y = 0; y < code.size; y++) {
    for (let x = 0; x < code.size; x++) {
      if (code.modules[y]![x]) path += `M${x + quiet},${y + quiet}h1v1h-1z`;
    }
  }
  const pixels = span * moduleSize;
  return `<?xml version="1.0" encoding="UTF-8"?>\n`
    + `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="${pixels}" height="${pixels}" `
    + `viewBox="0 0 ${span} ${span}" shape-rendering="crispEdges">\n`
    + `<rect width="${span}" height="${span}" fill="#ffffff"/>\n`
    + `<path d="${path}" fill="#000000"/>\n`
    + `</svg>\n`;
}
