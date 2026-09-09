// Fixture: a clean module with no ambient-authority construct — must never be flagged.
export const answer = 42;
export function pure(a: number, b: number): number { return a + b; }
