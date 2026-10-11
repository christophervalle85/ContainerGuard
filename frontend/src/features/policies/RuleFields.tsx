import type { PolicyRules } from '../../api/types';
export interface PolicyRuleFormValues {
  max_critical: string;
  max_high: string;
  require_sbom: boolean;
  unknown_severity_action: '' | PolicyRules['unknown_severity_action'];
}
export type RuleErrors = Partial<Record<keyof PolicyRuleFormValues, string>>;
interface Props {
  values: PolicyRuleFormValues;
  errors: RuleErrors;
  prefix: string;
  disabled: boolean;
  onChange: (values: PolicyRuleFormValues) => void;
}
export function RuleFields({
  values,
  errors,
  prefix,
  disabled,
  onChange,
}: Props) {
  return (
    <fieldset className="rule-fields" disabled={disabled}>
      <legend>Rules for this version</legend>
      <p className="field-help">
        A scan must satisfy every rule. Thresholds are whole numbers from 0 to
        2,147,483,647, inclusive.
      </p>
      <div className="rule-input-grid">
        {(['max_critical', 'max_high'] as const).map((field) => (
          <div className="field-group" key={field}>
            <label htmlFor={`${prefix}-${field}`}>
              Maximum {field === 'max_critical' ? 'CRITICAL' : 'HIGH'} findings
            </label>
            <input
              id={`${prefix}-${field}`}
              name={field}
              type="text"
              inputMode="numeric"
              value={values[field]}
              aria-invalid={!!errors[field] || undefined}
              aria-describedby={`${prefix}-${field}-help${errors[field] ? ` ${prefix}-${field}-error` : ''}`}
              onChange={(event) =>
                onChange({ ...values, [field]: event.target.value })
              }
            />
            <p className="field-help" id={`${prefix}-${field}-help`}>
              Fail when this severity's count exceeds the maximum.
            </p>
            {errors[field] && (
              <p className="field-error" id={`${prefix}-${field}-error`}>
                {errors[field]}
              </p>
            )}
          </div>
        ))}
        <div className="field-group">
          <label htmlFor={`${prefix}-unknown`}>Unknown severity action</label>
          <select
            id={`${prefix}-unknown`}
            value={values.unknown_severity_action}
            aria-invalid={!!errors.unknown_severity_action || undefined}
            aria-describedby={`${prefix}-unknown-help${errors.unknown_severity_action ? ` ${prefix}-unknown-error` : ''}`}
            onChange={(event) => {
              const value = event.target.value;
              if (value === '' || value === 'fail' || value === 'ignore')
                onChange({ ...values, unknown_severity_action: value });
            }}
          >
            <option value="">Choose an action</option>
            <option value="fail">Fail</option>
            <option value="ignore">Ignore</option>
          </select>
          <p className="field-help" id={`${prefix}-unknown-help`}>
            Choose whether any UNKNOWN finding rejects the scan or is ignored by
            this rule.
          </p>
          {errors.unknown_severity_action && (
            <p className="field-error" id={`${prefix}-unknown-error`}>
              {errors.unknown_severity_action}
            </p>
          )}
        </div>
      </div>
      <div className="checkbox-field">
        <input
          id={`${prefix}-sbom`}
          type="checkbox"
          checked={values.require_sbom}
          onChange={(event) =>
            onChange({ ...values, require_sbom: event.target.checked })
          }
          aria-describedby={`${prefix}-sbom-help`}
          aria-invalid={!!errors.require_sbom || undefined}
        />
        <label htmlFor={`${prefix}-sbom`}>Require an SBOM</label>
      </div>
      <p className="field-help" id={`${prefix}-sbom-help`}>
        Require an available saved software bill of materials to pass.
      </p>
      {errors.require_sbom && (
        <p className="field-error">{errors.require_sbom}</p>
      )}
    </fieldset>
  );
}
