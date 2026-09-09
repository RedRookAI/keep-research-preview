// Fixture: nobody imports this at all — no runtime edge, no type edge, no dynamic edge.
// UNREFERENCED (distinct from TYPE-ONLY-ISLAND: an island HAS an erased importer; this has none).
export function orphan(): number {
  return 4;
}
