import type { DistilledSkill, SkillJson, SkillProgramContract } from "./skill_distiller.js";

export type SkillProgram = (input: Readonly<Record<string, SkillJson>>) => SkillJson;
export type SkillPrograms = Readonly<Record<string, SkillProgram>>;

export type SkillProgramVerification =
  | { readonly ok: true; readonly casesPassed: number }
  | { readonly ok: false; readonly casesPassed: number; readonly detail: string };

/**
 * Execute a typed skill's portable examples against host-supplied deterministic code. The skill package
 * contains only an entrypoint name, JSON types, and examples, so portability does not grant code authority.
 */
export function verifySkillProgram(skill: DistilledSkill, programs: SkillPrograms): SkillProgramVerification {
  if (!skill.program) return { ok: true, casesPassed: 0 };
  const invalid = validateContract(skill.program);
  if (invalid) return { ok: false, casesPassed: 0, detail: invalid };
  const execute = programs[skill.program.entrypoint];
  if (!execute) return { ok: false, casesPassed: 0, detail: `unavailable program entrypoint: ${skill.program.entrypoint}` };

  let passed = 0;
  for (const example of skill.program.cases) {
    const typeError = validateInput(example.input, skill.program.inputs);
    if (typeError) return { ok: false, casesPassed: passed, detail: `case ${example.name}: ${typeError}` };
    let actual: SkillJson;
    try { actual = execute(example.input); }
    catch (error) { return { ok: false, casesPassed: passed, detail: `case ${example.name}: program threw: ${error instanceof Error ? error.message : String(error)}` }; }
    if (canonical(actual) !== canonical(example.expected)) {
      return { ok: false, casesPassed: passed, detail: `case ${example.name}: output did not match expected JSON` };
    }
    passed++;
  }
  return { ok: true, casesPassed: passed };
}

function validateContract(contract: SkillProgramContract): string | undefined {
  if (!contract.entrypoint.trim()) return "program entrypoint is empty";
  if (contract.cases.length === 0) return "program has no verification cases";
  for (const [name, type] of Object.entries(contract.inputs)) {
    if (!name || (type !== "string" && type !== "number" && type !== "boolean")) return `invalid input type for ${name || "<empty>"}`;
  }
  return undefined;
}

function validateInput(input: Readonly<Record<string, SkillJson>>, schema: Readonly<Record<string, string>>): string | undefined {
  for (const [name, type] of Object.entries(schema)) {
    if (!(name in input)) return `missing input ${name}`;
    if (typeof input[name] !== type) return `input ${name} must be ${type}`;
  }
  for (const name of Object.keys(input)) if (!(name in schema)) return `undeclared input ${name}`;
  return undefined;
}

function canonical(value: SkillJson): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as Readonly<Record<string, SkillJson>>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key]!)}`).join(",")}}`;
}
