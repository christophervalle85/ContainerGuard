import type { EvaluationRecord } from '../../api/types';
import { RuleSummary } from '../policies/RuleSummary';
export function EvaluationResult({
  evaluation,
}: {
  evaluation: EvaluationRecord;
}) {
  return (
    <article className={`evaluation-result evaluation-${evaluation.outcome}`}>
      <h3>
        {evaluation.outcome === 'passed'
          ? 'Policy passed'
          : evaluation.outcome === 'failed'
            ? 'Policy failed'
            : 'Evaluation error'}
      </h3>
      <p>
        {evaluation.outcome === 'error'
          ? 'The saved evidence could not be evaluated. This is not a policy rejection.'
          : evaluation.outcome === 'failed'
            ? 'The saved evidence does not satisfy this policy version.'
            : 'The saved evidence satisfies this policy version.'}
      </p>
      <h4>Saved finding counts</h4>
      <dl className="evaluation-counts">
        {Object.entries(evaluation.counts).map(([severity, count]) => (
          <div key={severity}>
            <dt>{severity}</dt>
            <dd>{count}</dd>
          </div>
        ))}
      </dl>
      <details className="evaluation-record">
        <summary>Saved rules and evaluation record</summary>
        <dl className="identity-grid">
          <div>
            <dt>Evaluation ID</dt>
            <dd>
              <code>{evaluation.evaluation_id}</code>
            </dd>
          </div>
          <div>
            <dt>Scan ID</dt>
            <dd>
              <code>{evaluation.scan_id}</code>
            </dd>
          </div>
          <div>
            <dt>Policy ID</dt>
            <dd>
              <code>{evaluation.policy_id}</code>
            </dd>
          </div>
          <div>
            <dt>Policy version {evaluation.version_number}</dt>
            <dd>
              <code>{evaluation.policy_version_id}</code>
            </dd>
          </div>
          <div>
            <dt>Saved at (UTC)</dt>
            <dd>
              <time dateTime={evaluation.created_at}>
                {evaluation.created_at}
              </time>
            </dd>
          </div>
          <div>
            <dt>Evaluator version</dt>
            <dd>{evaluation.evaluator_version}</dd>
          </div>
        </dl>
        <section aria-label="Saved rule snapshot">
          <h4>Saved rule snapshot</h4>
          <RuleSummary rules={evaluation.rule_snapshot} />
        </section>
      </details>
      <h4>Rule explanations</h4>
      <ul>
        {evaluation.rules.map((rule) => (
          <li key={rule.rule_id}>
            <strong>
              {rule.rule_id}: {rule.passed ? 'Passed' : 'Failed'}
            </strong>{' '}
            — {rule.reason} Actual: {String(rule.actual)}; expected:{' '}
            {String(rule.expected)}.
          </li>
        ))}
      </ul>
      {evaluation.error_code && (
        <p className="inline-error">
          {evaluation.error_code}:{' '}
          {evaluation.error_details ?? 'Saved evidence is invalid.'}
        </p>
      )}
    </article>
  );
}
