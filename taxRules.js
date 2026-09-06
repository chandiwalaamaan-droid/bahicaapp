// ---------------------------------------------------------------------------
// Indian income-tax rules, versioned by assessment year.
//
// WHY THIS FILE EXISTS: tax slabs used to be typed directly into the AI
// Advisor's system prompt as a string, and separately into the frontend's
// calculator as raw numbers. Both copies could (and did) drift out of date
// silently — nothing failed, it just quietly told users the wrong numbers
// for the wrong year. Keeping the rules in one object with an explicit
// `assessmentYear` and `effectiveFrom`/`effectiveTo` window makes staleness
// visible and gives future years a clear place to be added.
//
// NOTE: the frontend (a separately deployed app) keeps its own mirrored copy
// at src/taxRules.js for its calculator UI, since the two apps aren't bundled
// together. If they're ever deployed behind the same origin, the frontend
// should instead fetch GET /api/tax-rules (exposed below) and drop its local
// copy, so there is truly only one source of truth.
// ---------------------------------------------------------------------------

export const CURRENT_TAX_RULES = {
  assessmentYear: "AY 2026-27",
  financialYear: "FY 2025-26",
  effectiveFrom: "2025-04-01",
  effectiveTo: "2026-03-31",
  newRegime: {
    isDefault: true,
    standardDeductionSalaried: 75000,
    slabs: [
      [0, 400000, 0],
      [400000, 800000, 0.05],
      [800000, 1200000, 0.1],
      [1200000, 1600000, 0.15],
      [1600000, 2000000, 0.2],
      [2000000, 2400000, 0.25],
      [2400000, null, 0.3],
    ],
    section87ARebate: { maxTaxableIncome: 1200000, maxRebate: 60000 },
    cessRate: 0.04,
  },
  oldRegime: {
    standardDeductionSalaried: 50000,
    slabsBelow60: [
      [0, 250000, 0],
      [250000, 500000, 0.05],
      [500000, 1000000, 0.2],
      [1000000, null, 0.3],
    ],
    slabsSenior60to80: [
      [0, 300000, 0],
      [300000, 500000, 0.05],
      [500000, 1000000, 0.2],
      [1000000, null, 0.3],
    ],
    slabsSuperSenior80Plus: [
      [0, 500000, 0],
      [500000, 1000000, 0.2],
      [1000000, null, 0.3],
    ],
    section87ARebate: { maxTaxableIncome: 500000, maxRebate: 12500 },
    cessRate: 0.04,
    deductionCaps: {
      section80C: 150000,
      // 80D depends on who's covered, not just the taxpayer's own age. This is
      // still a simplification (it doesn't add the separate parents' cover
      // limit), but it at least reflects the taxpayer's own bracket instead
      // of a flat number regardless of age.
      section80DBelow60: 25000,
      section80D60Plus: 50000,
      section80CCD1B: 50000,
    },
  },
  // One line each, safe to interpolate into UI copy or the AI's system prompt.
  disclaimers: {
    calculator:
      "This is an estimate for general planning only — it doesn't account for surcharge on very high incomes, marginal relief, capital gains, or every deduction. It isn't a substitute for advice from a licensed CA or the official income tax e-filing calculator, especially before filing.",
    dashboard:
      "Simplified projection based on current ledger activity, scaled to a full year — not a filing calculation.",
  },
};

// Renders the new-regime slabs as a compact string for the AI prompt, e.g.
// "0-4L nil/4-8L 5%/8-12L 10%/...". Kept as a function (not a hardcoded
// string) so it always matches CURRENT_TAX_RULES.newRegime.slabs above.
function formatSlabsForPrompt(slabs) {
  return slabs
    .map(([from, to, rate]) => {
      const inLakh = (n) => n / 100000;
      const range = to === null ? `>${inLakh(from)}L` : `${from === 0 ? "0" : inLakh(from)}-${inLakh(to)}L`;
      return `${range} ${rate === 0 ? "nil" : `${rate * 100}%`}`;
    })
    .join("/");
}

export function taxRulesSummaryForPrompt(rules = CURRENT_TAX_RULES) {
  const newSlabText = formatSlabsForPrompt(rules.newRegime.slabs);
  const oldSlabText = formatSlabsForPrompt(rules.oldRegime.slabsBelow60);
  const rebateLakh = rules.newRegime.section87ARebate.maxTaxableIncome / 100000;
  return `${rules.financialYear} (${rules.assessmentYear}): new regime default, slabs ${newSlabText}, 87A rebate up to ${rebateLakh}L taxable income; old regime (below 60) slabs ${oldSlabText}.`;
}
