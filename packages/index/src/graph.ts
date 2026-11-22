import { IndexError } from './driver.ts';
import type { SqlDriver } from './driver.ts';
import { exists, integer, object, optionalString, string } from './event.ts';

const graphKinds = new Set(['node.created', 'node.merged', 'edge.inferred', 'layout.placed', 'layout.moved', 'layout.epoch']);
export const isGraphEvent = (kind: string): boolean => graphKinds.has(kind);

export function projectGraph(db: SqlDriver): void {
  db.exec('DELETE FROM graph_nodes');
  let epoch = 0;
  const events = db.prepare(`
    SELECT g.event_seq, g.kind, g.body, o.profile FROM graph_events g
    JOIN event_origin o USING (event_seq) WHERE g.event_seq > ? ORDER BY g.event_seq LIMIT 128
  `);
  const remove = db.prepare('DELETE FROM graph_events WHERE event_seq = ?');
  const replace = db.prepare('UPDATE graph_events SET body = ? WHERE event_seq = ?');
  let after = 0;
  for (;;) {
    const batch = events.all(after);
    if (!batch.length) break;
    for (const row of batch) {
      const seq = row.event_seq as number;
      after = seq;
      const kind = row.kind as string;
      const body = object(JSON.parse(row.body as string), kind);
      const hasNode = (id: string) => exists(db, 'SELECT 1 FROM graph_nodes WHERE node_id = ?', id);
      const hasEvidence = (id: number) => exists(db, 'SELECT 1 FROM event_origin WHERE event_seq = ?', id);

      switch (kind) {
        case 'node.created': {
          if (body.evidence_event_seq !== undefined &&
              !hasEvidence(integer(body.evidence_event_seq, 'evidence_event_seq'))) {
            remove.run(seq);
            break;
          }
          const canonical = string(body.canonical_key, 'canonical_key');
          db.prepare('INSERT INTO graph_nodes (node_id, kind, canonical_key, label, profile) VALUES (?, ?, ?, ?, ?)')
            .run(string(body.node_id, 'node_id'), string(body.kind, 'node kind'), canonical,
              optionalString(body.label, 'label') ?? canonical, row.profile);
          break;
        }
        case 'edge.inferred': {
          const src = string(body.src, 'src');
          const dst = string(body.dst, 'dst');
          if (!hasNode(src) || !hasNode(dst)) {
            remove.run(seq);
            break;
          }
          const refs = Array.isArray(body.evidence) ? body.evidence : [body.evidence_event_seq];
          const evidence = [...new Set(refs.map(value => integer(value, 'evidence event sequence')))]
            .filter(hasEvidence).sort((a, b) => a - b);
          if (!evidence.length) {
            remove.run(seq);
            break;
          }
          if (Array.isArray(body.evidence) && evidence.length !== refs.length) {
            body.evidence = evidence;
            replace.run(JSON.stringify(body), seq);
          }
          if (typeof body.confidence !== 'number' || !(body.confidence >= 0 && body.confidence <= 1)) {
            throw new IndexError('PROJECTION', 'Expected graph confidence between zero and one.');
          }
          db.prepare(`
            INSERT INTO graph_edges (edge_id, src, dst, kind, evidence_event_seq, inferred, confidence)
            VALUES (?, ?, ?, ?, ?, 1, ?)
          `).run(seq, src, dst, string(body.kind, 'edge kind'), evidence[0], body.confidence);
          const insert = db.prepare('INSERT INTO graph_edge_evidence VALUES (?, ?)');
          for (const ref of evidence) insert.run(seq, ref);
          break;
        }
        case 'layout.epoch':
          epoch = integer(body.epoch, 'epoch');
          db.exec('DELETE FROM graph_positions');
          break;
        case 'layout.placed':
        case 'layout.moved': {
          const id = string(body.node_id, 'node_id');
          if (!hasNode(id)) {
            remove.run(seq);
            break;
          }
          db.prepare(`
            INSERT INTO graph_positions VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET epoch=excluded.epoch, x=excluded.x, y=excluded.y,
              z=excluded.z, placed_event_seq=excluded.placed_event_seq
          `).run(id, body.epoch === undefined ? epoch : integer(body.epoch, 'epoch'), integer(body.x, 'x'),
            integer(body.y, 'y'), body.z === undefined ? 0 : integer(body.z, 'z'), seq);
          break;
        }
        case 'node.merged': {
          const id = string(body.node_id, 'node_id');
          const survivor = string(body.survivor_id, 'survivor_id');
          if (id === survivor || !hasNode(id) || !hasNode(survivor)) {
            remove.run(seq);
            break;
          }
          db.prepare('UPDATE graph_nodes SET merged_into = ? WHERE node_id = ?').run(survivor, id);
          db.prepare('UPDATE graph_edges SET src = ? WHERE src = ?').run(survivor, id);
          db.prepare('UPDATE graph_edges SET dst = ? WHERE dst = ?').run(survivor, id);
          db.prepare(`
            UPDATE graph_positions SET node_id = ? WHERE node_id = ?
              AND NOT EXISTS (SELECT 1 FROM graph_positions WHERE node_id = ?)
          `).run(survivor, id, survivor);
          db.prepare('DELETE FROM graph_positions WHERE node_id = ?').run(id);
          break;
        }
      }
    }
  }
}
