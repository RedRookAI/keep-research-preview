/**
 * Bounded TAP 13/14 interpretation for configured commands. Plans and numbered
 * points establish stream completeness, not assertion quality or trustworthy tests.
 * Four-space subtests and opaque YAML diagnostics follow the TAP protocol. An
 * unsupported/malformed declared stream is a harness refusal, never an exit-code
 * fallback. Non-TAP commands retain a distinctly named command-exit check.
 */
import type { TestCaseResult, TestRunResult } from "./validate.js";

interface Point { id: number; name: string; passed: boolean; raw: string; directive?: string; child?: Frame; suite?: boolean }
interface Frame { points: Point[]; plan?: number; tailPlan?: boolean; pending?: Frame }
interface Analysis { recognized: boolean; results: TestCaseResult[]; error?: string }

function analyzeTap(output: string): Analysis {
  const lines = output.split(/\r?\n/);
  // A root point also claims TAP: a passing prefix without its plan is incomplete.
  const recognized = lines.some(line => /^(?:TAP version\b|1\.\.|(?:not )?ok\b|Bail out!)/i.test(line.trim()));
  if (!recognized) return { recognized: false, results: [] };
  const root: Frame = { points: [] }, stack: Frame[] = [root];
  let yaml: { indent: number; owner: Point } | undefined;
  let error: string | undefined;
  const refuse = (reason: string) => { error ??= reason; };
  const close = () => {
    const child = stack.pop()!;
    const parent = stack[stack.length - 1]!;
    if (parent.pending) refuse("child stream has no terminating parent point");
    parent.pending = child;
  };
  for (const raw of lines) {
    const indent = raw.length - raw.trimStart().length, line = raw.trim();
    if (yaml) {
      if (indent === yaml.indent && line === "...") yaml = undefined;
      // Only the simple scalar Node suite marker is interpreted. All other YAML
      // (including literal blocks containing apparent test points) is opaque.
      else if (indent === yaml.indent && /^type:\s*(?:'suite'|"suite"|suite)\s*$/.test(line)) yaml.owner.suite = true;
      continue;
    }
    if (!line || line.startsWith("#")) continue;
    if (line === "---") {
      const owner = stack[stack.length - 1]!.points.at(-1);
      if (!owner || indent !== (stack.length - 1) * 4 + 2) refuse("unattached YAML diagnostics");
      else yaml = { indent, owner };
      continue;
    }
    if (/^Bail out!/i.test(line)) { refuse("TAP bailout"); continue; }
    if (/^TAP version\b/.test(line)) {
      if (indent !== 0 || !/^TAP version (13|14)$/.test(line) || root.points.length || root.plan !== undefined) refuse("unsupported or misplaced TAP version");
      continue;
    }
    const plan = /^1\.\.(\d+)(?:\s+#.*)?$/.exec(line);
    const point = /^(ok|not ok)(?:\s+(\d+))?(?:\s+-)?(?:\s+(.*))?$/.exec(line);
    if (!plan && !point) {
      // TAP permits unrelated diagnostic output. A malformed record claiming TAP
      // syntax is different: do not silently drop a broken plan/test point.
      if (/^(?:1\.\.|(?:not )?ok\b)/i.test(line)) refuse("malformed TAP record");
      continue;
    }
    if (indent % 4 !== 0 || indent / 4 > 64) { refuse("unsupported TAP indentation"); continue; }
    const depth = indent / 4;
    while (stack.length - 1 > depth) close();
    // A nested suite may start with comments followed by its deepest leaf. Its
    // enclosing plans/terminating points arrive later; validate all of them below.
    while (depth >= stack.length) stack.push({ points: [] });
    const frame = stack[depth]!;
    if (plan) {
      if (frame.plan !== undefined || frame.pending) refuse("duplicate plan or unterminated child");
      frame.plan = Number(plan[1]);
      if (!Number.isSafeInteger(frame.plan)) refuse("invalid plan size");
      frame.tailPlan = frame.points.length > 0;
      continue;
    }
    if (frame.tailPlan) refuse("test point after trailing plan");
    let name = point![3] ?? "", directive: string | undefined;
    // TAP's first unescaped comment delimiter determines the directive. A test
    // named "literal \\# TODO" remains an ordinary test.
    for (let i = 0; i < name.length; i++) {
      if (name[i] !== "#" || (i > 0 && !/\s/.test(name[i - 1]!))) continue;
      let escapes = 0; for (let j = i - 1; j >= 0 && name[j] === "\\"; j--) escapes++;
      if (escapes % 2) continue;
      directive = /^(SKIP|TODO)\b/i.exec(name.slice(i + 1).trim())?.[1]?.toUpperCase();
      name = name.slice(0, i); break;
    }
    const id = point![2] === undefined ? frame.points.length + 1 : Number(point![2]);
    frame.points.push({ id, name: name.trim().replace(/\\([#\\])/g, "$1") || `test ${id}`, passed: point![1] === "ok", raw: line,
      ...(directive ? { directive } : {}), ...(frame.pending ? { child: frame.pending } : {}) });
    delete frame.pending;
  }
  if (yaml) refuse("unterminated YAML diagnostics");
  while (stack.length > 1) close();
  const results: TestCaseResult[] = [];
  const visit = (frame: Frame, suppressed = false) => {
    if (frame.pending) refuse("child stream has no terminating parent point");
    if (frame.plan === undefined || frame.plan !== frame.points.length) refuse("missing or incomplete TAP plan");
    const ids = new Set<number>();
    for (const p of frame.points) {
      if (!Number.isSafeInteger(p.id) || p.id < 1 || p.id > (frame.plan ?? 0) || ids.has(p.id)) refuse("duplicate or out-of-range TAP point ID");
      ids.add(p.id);
      const excluded = suppressed || !!p.directive;
      if (p.child) visit(p.child, excluded);
      if (!excluded && (!p.child && !p.suite || !p.passed)) results.push({ name: p.name, passed: p.passed, ...(!p.passed ? { output: p.raw } : {}) });
    }
  };
  visit(root);
  return { recognized: true, results, ...(error ? { error } : {}) };
}

/** Eligible completed points only. A malformed TAP stream returns a failure,
 * never its passing prefix. No TAP returns [] (not an execution success). */
export function parseTap(output: string): TestCaseResult[] {
  const tap = analyzeTap(output);
  return tap.error ? [{ name: "TAP evidence", passed: false, output: tap.error }] : tap.results;
}

/** Shared by ordinary, container, Windows and verified-guest result translators.
 * Only stdout supplies TAP; stderr cannot add or overwrite test results. No new
 * receipt fields: refusal reasons are in the existing bound runnerError field. */
export function interpretCommandTests(command: string, res: { stdout: string; stderr: string; code: number; truncated?: boolean }): TestRunResult {
  const hold = (why: string): TestRunResult => ({ results: [], runnerError: why, failureKind: "harness" });
  if (res.truncated) return hold("test output was truncated; execution evidence is incomplete");
  const tap = analyzeTap(res.stdout);
  if (tap.error) return hold(`invalid TAP evidence: ${tap.error}`);
  if (tap.recognized && tap.results.length === 0) return hold("TAP completed with no eligible executed tests (empty, skipped, TODO or empty suites)");
  if (tap.recognized && (res.code === 0 || tap.results.some(c => !c.passed))) return { results: tap.results };
  const name = `command exit: ${command}`;
  return { results: [{ name, passed: res.code === 0,
    ...(res.code !== 0 ? { output: (res.stderr || res.stdout).slice(-2000) || `exit code ${res.code}` } : {}) }] };
}
