/** Stable observation order, not a change to compilation-unit identity or policy. */
export function orderCompilationUnits(units) {
  const ids = new Set();
  for (const unit of units) {
    if (typeof unit.unitId !== "string" || unit.unitId.length === 0 || ids.has(unit.unitId))
      throw new Error("P2 missing or duplicate compilation unit identity");
    ids.add(unit.unitId);
  }
  return [...units].sort((a, b) => a.unitId.localeCompare(b.unitId));
}
