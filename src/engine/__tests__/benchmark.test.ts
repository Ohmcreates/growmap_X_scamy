import { describe, expect, it } from 'vitest';
import { BENCHMARK_CORPUS } from '../benchmarks.js';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Phase 8 Evaluation & Benchmark Harness', () => {
  it('evaluates entire benchmark corpus and generates confusion matrix', () => {
    let tp = 0; // Scam correctly flagged Medium or High
    let fn = 0; // Scam missed (flagged Low)
    let tn = 0; // Benign correctly flagged Low
    let fp = 0; // Benign incorrectly flagged Medium or High
    let highFalsePositives = 0;

    const totalScams = BENCHMARK_CORPUS.filter((c) => c.category === 'SCAM').length;
    const totalBenign = BENCHMARK_CORPUS.filter((c) => c.category === 'BENIGN').length;

    for (const testCase of BENCHMARK_CORPUS) {
      const result = analyzeMessage(testCase.text);
      const isFlagged = result.riskLevel === 'MEDIUM' || result.riskLevel === 'HIGH';

      if (testCase.category === 'SCAM') {
        if (isFlagged) {
          tp++;
        } else {
          fn++;
          console.warn(`[FALSE NEGATIVE] Test ${testCase.id} missed:`, result.score, testCase.text);
        }

        if (testCase.expectedRules) {
          const firedIds = result.breakdown.map((b) => b.ruleId);
          for (const rule of testCase.expectedRules) {
            expect(firedIds, `Test ${testCase.id} should have fired rule ${rule}`).toContain(rule);
          }
        }
      } else {
        // BENIGN
        if (!isFlagged) {
          tn++;
        } else {
          fp++;
          if (result.riskLevel === 'HIGH') {
            highFalsePositives++;
          }
          console.warn(`[FALSE POSITIVE] Test ${testCase.id} incorrectly flagged:`, result.score, testCase.text);
        }

        if (testCase.forbiddenRules) {
          const firedIds = result.breakdown.map((b) => b.ruleId);
          for (const rule of testCase.forbiddenRules) {
            expect(firedIds, `Test ${testCase.id} must not fire rule ${rule}`).not.toContain(rule);
          }
        }
      }
    }

    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);
    const fpr = fp / (fp + tn);

    console.log('\n======================================================');
    console.log('       SCAM SPOTTER BENCHMARK CONFUSION MATRIX        ');
    console.log('======================================================');
    console.log(`Total Samples: ${BENCHMARK_CORPUS.length} (Scams: ${totalScams}, Benign: ${totalBenign})`);
    console.log(`True Positives (Scams caught):     ${tp} / ${totalScams}`);
    console.log(`False Negatives (Scams missed):     ${fn} / ${totalScams}`);
    console.log(`True Negatives (Benign safe):      ${tn} / ${totalBenign}`);
    console.log(`False Positives (Benign flagged):  ${fp} / ${totalBenign}`);
    console.log('------------------------------------------------------');
    console.log(`Precision:            ${(precision * 100).toFixed(1)}%`);
    console.log(`Recall:               ${(recall * 100).toFixed(1)}%`);
    console.log(`False Positive Rate:  ${(fpr * 100).toFixed(1)}%`);
    console.log(`High-Risk False Pos:  ${highFalsePositives}`);
    console.log('======================================================\n');

    // Quality gate assertions
    expect(recall).toBeGreaterThanOrEqual(0.95);
    expect(precision).toBeGreaterThanOrEqual(0.95);
    expect(highFalsePositives).toBe(0); // Zero legitimate messages marked High!
  });
});
