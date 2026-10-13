import { MatchEvidence } from '../engine/types.js';

export interface MergedHighlightSpan {
  start: number;
  end: number;
  rules: { ruleId: string; label: string; category: string }[];
  matchedText: string;
}

export function mergeHighlightSpans(
  originalText: string,
  evidence: MatchEvidence[]
): MergedHighlightSpan[] {
  if (evidence.length === 0) return [];

  // Sort by start index ascending, then by length descending
  const sorted = [...evidence].sort(
    (a, b) => a.startIndex - b.startIndex || (b.endIndex - b.startIndex) - (a.endIndex - a.startIndex)
  );

  const merged: MergedHighlightSpan[] = [];
  let current: MergedHighlightSpan = {
    start: sorted[0].startIndex,
    end: sorted[0].endIndex,
    rules: [
      {
        ruleId: sorted[0].ruleId,
        label: sorted[0].ruleLabel,
        category: sorted[0].category,
      },
    ],
    matchedText: originalText.slice(sorted[0].startIndex, sorted[0].endIndex),
  };

  for (let i = 1; i < sorted.length; i++) {
    const next = sorted[i];

    // Check if overlapping or touching
    if (next.startIndex <= current.end) {
      current.end = Math.max(current.end, next.endIndex);
      current.matchedText = originalText.slice(current.start, current.end);

      // Add rule if not already present in this merged span
      if (!current.rules.some((r) => r.ruleId === next.ruleId)) {
        current.rules.push({
          ruleId: next.ruleId,
          label: next.ruleLabel,
          category: next.category,
        });
      }
    } else {
      merged.push(current);
      current = {
        start: next.startIndex,
        end: next.endIndex,
        rules: [
          {
            ruleId: next.ruleId,
            label: next.ruleLabel,
            category: next.category,
          },
        ],
        matchedText: originalText.slice(next.startIndex, next.endIndex),
      };
    }
  }

  merged.push(current);
  return merged;
}

export function renderHighlightedDom(
  originalText: string,
  spans: MergedHighlightSpan[],
  onHighlightClick?: (ruleId: string) => void
): DocumentFragment {
  const fragment = document.createDocumentFragment();
  let cursor = 0;

  for (const span of spans) {
    // 1. Text before highlight
    if (span.start > cursor) {
      const beforeText = originalText.slice(cursor, span.start);
      fragment.appendChild(document.createTextNode(beforeText));
    }

    // 2. Highlight mark
    const mark = document.createElement('mark');
    const primaryRule = span.rules[0];
    const categoryClass = primaryRule.category
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-');

    mark.className = `highlight-span cat-${categoryClass}`;
    mark.setAttribute(
      'aria-label',
      `Warning: ${span.rules.map((r) => r.label).join(', ')}`
    );
    mark.setAttribute('tabindex', '0');
    mark.setAttribute('data-rule-id', primaryRule.ruleId);

    // Text content inside mark (Strictly safe text node, zero innerHTML)
    mark.appendChild(document.createTextNode(span.matchedText));

    // Optional tooltip title
    mark.title = `${span.rules.map((r) => r.label).join(' & ')} (Click to view rule explanation)`;

    if (onHighlightClick) {
      mark.addEventListener('click', () => onHighlightClick(primaryRule.ruleId));
      mark.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onHighlightClick(primaryRule.ruleId);
        }
      });
    }

    fragment.appendChild(mark);
    cursor = span.end;
  }

  // 3. Trailing text
  if (cursor < originalText.length) {
    const remainingText = originalText.slice(cursor);
    fragment.appendChild(document.createTextNode(remainingText));
  }

  return fragment;
}
