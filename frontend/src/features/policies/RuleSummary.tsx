import type { PolicyRules } from '../../api/types';
export function RuleSummary({ rules }: { rules: PolicyRules }) {
  return (
    <dl className="rule-summary">
      <div>
        <dt>Maximum CRITICAL findings</dt>
        <dd>{rules.max_critical}</dd>
      </div>
      <div>
        <dt>Maximum HIGH findings</dt>
        <dd>{rules.max_high}</dd>
      </div>
      <div>
        <dt>SBOM</dt>
        <dd>{rules.require_sbom ? 'Required' : 'Optional'}</dd>
      </div>
      <div>
        <dt>Unknown severity action</dt>
        <dd>{rules.unknown_severity_action === 'fail' ? 'Fail' : 'Ignore'}</dd>
      </div>
    </dl>
  );
}
