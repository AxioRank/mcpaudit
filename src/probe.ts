/**
 * `mcpaudit probe` runs the bundled red-team corpus through the AxioRank engine's
 * DEFAULT posture and reports the catch rate. It is a self-test of the detection
 * engine, not an active attack on a third-party server: mcpaudit never calls a
 * live server's tools with adversarial input. It answers "if my agent made these
 * calls, would the engine catch them?".
 */

import { localDecision, scoreToolCall } from "@axiorank/detectors";
import { CORPUS, freeTierCorpus, isAttack, type Scenario } from "@axiorank/redteam-corpus";

export interface ProbeOutcome {
  id: string;
  title: string;
  category: string;
  attack: boolean;
  expected: string;
  /** Did the default posture produce the protective outcome? */
  caught: boolean;
  decision: "allow" | "deny" | "hold";
}

export interface ProbeReport {
  outcomes: ProbeOutcome[];
  attacks: number;
  caughtAttacks: number;
  benign: number;
  falsePositives: number;
  catchRate: number;
}

function evaluate(scenario: Scenario): ProbeOutcome {
  // Local default posture covers single-call scenarios; multi-step kill chains
  // need the hosted gateway's taint propagation, so probe scores their first
  // step only (still a meaningful signal check).
  const step = scenario.steps[0];
  const expected = scenario.expected.outcome;
  const attack = isAttack(expected);
  if (!step) {
    return {
      id: scenario.id,
      title: scenario.title,
      category: scenario.category,
      attack,
      expected,
      caught: false,
      decision: "allow",
    };
  }

  const scored = scoreToolCall(step.tool, step.arguments);
  const verdict = localDecision(scored.score, scored.signals);
  const hasCategory = (cat?: string) =>
    cat ? scored.signals.some((s) => s.category === cat) : scored.signals.length > 0;

  let caught: boolean;
  switch (expected) {
    case "deny":
      caught = verdict.decision === "deny";
      break;
    case "require_approval":
      caught = verdict.decision === "deny" || verdict.decision === "hold";
      break;
    case "flag":
      caught = hasCategory(scenario.expected.signalCategory);
      break;
    case "redact":
      caught = scored.signals.some((s) => s.category === "secret" || s.category === "pii");
      break;
    case "allow":
      // A benign control is "caught" (handled correctly) when NOT blocked.
      caught = verdict.decision === "allow";
      break;
    default:
      caught = false;
  }

  return {
    id: scenario.id,
    title: scenario.title,
    category: scenario.category,
    attack,
    expected,
    caught,
    decision: verdict.decision,
  };
}

export function runProbe(full: boolean): ProbeReport {
  const scenarios = (full ? CORPUS : freeTierCorpus()).filter((s) => s.kind === "single");
  const outcomes = scenarios.map(evaluate);
  const attackOutcomes = outcomes.filter((o) => o.attack);
  const benignOutcomes = outcomes.filter((o) => !o.attack);
  const caughtAttacks = attackOutcomes.filter((o) => o.caught).length;
  const falsePositives = benignOutcomes.filter((o) => !o.caught).length;
  return {
    outcomes,
    attacks: attackOutcomes.length,
    caughtAttacks,
    benign: benignOutcomes.length,
    falsePositives,
    catchRate: attackOutcomes.length === 0 ? 1 : caughtAttacks / attackOutcomes.length,
  };
}
