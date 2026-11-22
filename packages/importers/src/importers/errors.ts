import type { ItemErrorCode, ItemErrorInfo } from '../types.js';

export class ItemSkipError extends Error {
  readonly code: ItemErrorCode;
  readonly source: string;
  readonly entryPath: string;
  readonly itemPath: string;
  readonly limitBytes?: number;
  readonly observedBytes?: number;

  constructor(info: ItemErrorInfo) {
    super(`${info.code}: ${info.message}`);
    this.name = 'ItemSkipError';
    this.code = info.code;
    this.source = info.source;
    this.entryPath = info.entryPath;
    this.itemPath = info.itemPath;
    this.limitBytes = info.limitBytes;
    this.observedBytes = info.observedBytes;
  }

  toInfo(): ItemErrorInfo {
    return {
      code: this.code,
      source: this.source,
      entryPath: this.entryPath,
      itemPath: this.itemPath,
      message: this.message,
      limitBytes: this.limitBytes,
      observedBytes: this.observedBytes,
    };
  }
}
