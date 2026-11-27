/**
 * The printable chain-head anchor (Architecture 4.5, 8.1 step 9, 8.2): vault ID, epoch, segment number, manifest
 * hash and the SHA-256 fingerprint of the signing public key. It is shown as text and as a QR code. Comparing a
 * drive against an independent anchor is what makes rollback and whole-drive replacement detectable; the chain
 * alone is only tamper-evident: it shows a change, it cannot stop one.
 */
import { Buffer } from 'node:buffer';
import { check, hex, integer, sha256 } from './bytes.ts';
import { GENESIS_HASH } from './manifest.ts';
import { encodeQr, renderQrSvg, renderQrText } from './qr.ts';
import type { QrCode } from './qr.ts';
import type { VaultAnchor } from './vault-directory.ts';

export const ANCHOR_PREFIX = 'foundry-anchor/1';

/** The anchor of a verified head. `signingPublicKey` is the base64 field of VAULT.json. */
export function chainAnchor(vaultId: string, signingPublicKey: string, head: { segment: number; hash: string }): VaultAnchor {
  hex(vaultId, 16);
  integer(head.segment);
  hex(head.hash, 32);
  if (head.segment === 0) check(head.hash === GENESIS_HASH, 'ANCHOR');
  const key = Buffer.from(signingPublicKey, 'base64');
  check(key.length === 32 && key.toString('base64') === signingPublicKey, 'KEY');
  return { vaultId, epoch: 1, segment: head.segment, manifestHash: head.hash, signingKeyFingerprint: sha256(key) };
}

/** The compact one-line form that the QR code carries. */
export function anchorPayload(anchor: VaultAnchor): string {
  return `${ANCHOR_PREFIX};vault=${anchor.vaultId};epoch=${anchor.epoch};segment=${anchor.segment};`
    + `manifest=${anchor.manifestHash};key=${anchor.signingKeyFingerprint}`;
}

/** Parse the compact form (from a scanned QR code or typed back). Throws `ANCHOR` on any deviation. */
export function parseAnchor(text: string): VaultAnchor {
  const match = /^foundry-anchor\/1;vault=([0-9a-f]{32});epoch=1;segment=(0|[1-9][0-9]{0,15});manifest=([0-9a-f]{64});key=([0-9a-f]{64})$/u
    .exec(text.trim());
  check(match, 'ANCHOR');
  const segment = Number(match[2]);
  check(Number.isSafeInteger(segment), 'ANCHOR');
  if (segment === 0) check(match[3] === GENESIS_HASH, 'ANCHOR');
  return { vaultId: match[1]!, epoch: 1, segment, manifestHash: match[3]!, signingKeyFingerprint: match[4]! };
}

/** Human-readable text, grouped in fours so it can be read aloud or compared by eye. */
export function anchorText(anchor: VaultAnchor): string {
  const group = (value: string) => value.match(/.{1,4}/gu)!.join(' ');
  return [
    'Foundry chain-head anchor (keep it apart from both copies)',
    `  vault id     ${group(anchor.vaultId)}`,
    `  epoch        ${anchor.epoch}`,
    `  segment      ${anchor.segment}`,
    `  manifest     ${group(anchor.manifestHash.slice(0, 32))}`,
    `               ${group(anchor.manifestHash.slice(32))}`,
    `  key sha-256  ${group(anchor.signingKeyFingerprint.slice(0, 32))}`,
    `               ${group(anchor.signingKeyFingerprint.slice(32))}`,
    `  compact      ${anchorPayload(anchor)}`,
  ].join('\n') + '\n';
}

export function anchorQr(anchor: VaultAnchor): QrCode {
  return encodeQr(Buffer.from(anchorPayload(anchor)), { errorCorrection: 'M' });
}

export function anchorQrText(anchor: VaultAnchor, options?: { invert?: boolean }): string {
  return renderQrText(anchorQr(anchor), options);
}

export function anchorQrSvg(anchor: VaultAnchor): string {
  return renderQrSvg(anchorQr(anchor));
}
