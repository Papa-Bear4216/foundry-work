export { IndexError, openSqlDriver, SQLCIPHER_PARAMETERS } from './driver.ts';
export type { IndexPolicy, OpenOptions, SqlDriver, SqlStatement, SqlValue } from './driver.ts';
export { applyIncremental, initializeSchema } from './projection.ts';
export type { DeriveItem, ProjectionOptions, ProjectionResult } from './projection.ts';
export { search } from './search.ts';
export type { SearchHit, SearchOptions } from './search.ts';
export { rebuildIndex, searchIndex, updateIndex } from './store.ts';
export type { IndexStoreOptions } from './store.ts';
