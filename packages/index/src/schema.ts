export const SCHEMA_VERSION = 1;

export const SCHEMA_SQL = `
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;

CREATE TABLE projection_state (
  projection TEXT PRIMARY KEY,
  deriver_version INTEGER NOT NULL,
  last_event_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE hidden (
  scope TEXT NOT NULL CHECK (scope IN ('item', 'event', 'collection', 'profile', 'key', 'tombstone')),
  target TEXT NOT NULL,
  PRIMARY KEY (scope, target)
) STRICT;

CREATE TABLE event_origin (
  event_seq INTEGER PRIMARY KEY,
  key_id TEXT NOT NULL,
  profile TEXT,
  collection TEXT
) STRICT;

CREATE TABLE graph_events (
  event_seq INTEGER PRIMARY KEY REFERENCES event_origin ON DELETE CASCADE,
  kind TEXT NOT NULL,
  body TEXT NOT NULL CHECK (json_valid(body))
) STRICT;

CREATE TABLE items (
  item_id TEXT PRIMARY KEY,
  event_seq INTEGER NOT NULL UNIQUE REFERENCES event_origin ON DELETE CASCADE,
  source TEXT NOT NULL,
  profile TEXT NOT NULL,
  collection TEXT NOT NULL,
  tier TEXT NOT NULL,
  sensitivity TEXT,
  title TEXT,
  path TEXT,
  mime TEXT,
  size INTEGER,
  source_at TEXT,
  imported_at TEXT NOT NULL,
  blob_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  derived INTEGER NOT NULL DEFAULT 0 CHECK (derived IN (0, 1))
) STRICT;
CREATE INDEX items_blob ON items(key_id, blob_id, derived);
CREATE INDEX items_filters ON items(profile, collection, source, tier, imported_at);

CREATE TABLE chunks (
  chunk_id INTEGER PRIMARY KEY,
  item_id TEXT NOT NULL REFERENCES items ON DELETE CASCADE,
  ord INTEGER NOT NULL,
  text TEXT NOT NULL,
  UNIQUE (item_id, ord)
) STRICT;
CREATE VIRTUAL TABLE chunks_fts USING fts5(
  text, content='chunks', content_rowid='chunk_id', tokenize='porter unicode61'
);
CREATE TRIGGER chunks_ai AFTER INSERT ON chunks BEGIN
  INSERT INTO chunks_fts(rowid, text) VALUES (new.chunk_id, new.text);
END;
CREATE TRIGGER chunks_ad AFTER DELETE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES ('delete', old.chunk_id, old.text);
END;
CREATE TRIGGER chunks_au AFTER UPDATE ON chunks BEGIN
  INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES ('delete', old.chunk_id, old.text);
  INSERT INTO chunks_fts(rowid, text) VALUES (new.chunk_id, new.text);
END;

CREATE TABLE vectors (
  chunk_id INTEGER PRIMARY KEY REFERENCES chunks ON DELETE CASCADE,
  model TEXT NOT NULL,
  dim INTEGER NOT NULL CHECK (dim > 0),
  scale REAL NOT NULL CHECK (scale > 0),
  q8 BLOB NOT NULL CHECK (length(q8) = dim)
) STRICT;

CREATE TABLE blob_locator (
  blob_id TEXT NOT NULL,
  collection TEXT NOT NULL,
  segment INTEGER NOT NULL,
  file TEXT NOT NULL,
  offset INTEGER NOT NULL,
  length INTEGER NOT NULL,
  header_sha256 TEXT NOT NULL,
  PRIMARY KEY (collection, blob_id)
) STRICT;

CREATE TABLE places (
  place_id INTEGER PRIMARY KEY,
  item_id TEXT NOT NULL REFERENCES items ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  lat_e7 INTEGER NOT NULL CHECK (lat_e7 BETWEEN -900000000 AND 900000000),
  lng_e7 INTEGER NOT NULL CHECK (lng_e7 BETWEEN -1800000000 AND 1800000000),
  accuracy_m INTEGER CHECK (accuracy_m >= 0)
) STRICT;
CREATE VIRTUAL TABLE places_rtree USING rtree_i32(place_id, min_lat, max_lat, min_lng, max_lng);
CREATE TRIGGER places_ai AFTER INSERT ON places BEGIN
  INSERT INTO places_rtree VALUES (new.place_id, new.lat_e7, new.lat_e7, new.lng_e7, new.lng_e7);
END;
CREATE TRIGGER places_ad AFTER DELETE ON places BEGIN
  DELETE FROM places_rtree WHERE place_id = old.place_id;
END;
CREATE TRIGGER places_au AFTER UPDATE ON places BEGIN
  DELETE FROM places_rtree WHERE place_id = old.place_id;
  INSERT INTO places_rtree VALUES (new.place_id, new.lat_e7, new.lat_e7, new.lng_e7, new.lng_e7);
END;

CREATE TABLE graph_nodes (
  node_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  canonical_key TEXT NOT NULL,
  label TEXT NOT NULL,
  profile TEXT,
  merged_into TEXT REFERENCES graph_nodes ON DELETE SET NULL,
  UNIQUE (kind, canonical_key)
) STRICT;
CREATE TABLE graph_edges (
  edge_id INTEGER PRIMARY KEY,
  src TEXT NOT NULL REFERENCES graph_nodes ON DELETE CASCADE,
  dst TEXT NOT NULL REFERENCES graph_nodes ON DELETE CASCADE,
  kind TEXT NOT NULL,
  evidence_event_seq INTEGER NOT NULL,
  inferred INTEGER NOT NULL DEFAULT 0 CHECK (inferred IN (0, 1)),
  confidence REAL CHECK (confidence BETWEEN 0 AND 1),
  CHECK (inferred = 0 OR confidence IS NOT NULL)
) STRICT;
CREATE TABLE graph_edge_evidence (
  edge_id INTEGER NOT NULL REFERENCES graph_edges ON DELETE CASCADE,
  event_seq INTEGER NOT NULL REFERENCES event_origin ON DELETE CASCADE,
  PRIMARY KEY (edge_id, event_seq)
) STRICT;
CREATE TABLE graph_positions (
  node_id TEXT PRIMARY KEY REFERENCES graph_nodes ON DELETE CASCADE,
  epoch INTEGER NOT NULL,
  x INTEGER NOT NULL,
  y INTEGER NOT NULL,
  z INTEGER NOT NULL DEFAULT 0,
  placed_event_seq INTEGER NOT NULL
) STRICT;
`;
