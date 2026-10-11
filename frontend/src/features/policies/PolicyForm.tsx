import { useEffect, useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { ApiError } from '../../api/client';
import { createPolicy, createPolicyVersion } from '../../api/policies';
import { policyRulesSchema } from '../../api/types';
import type { PolicyVersionRecord } from '../../api/types';
import { RuleFields } from './RuleFields';
import type { PolicyRuleFormValues, RuleErrors } from './RuleFields';
interface Props {
  policyId?: string;
  onCreated: (record: PolicyVersionRecord) => void;
  onCheckHistory?: () => void;
}
type Errors = RuleErrors & { name?: string };
function threshold(value: string): number | null {
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= 2147483647 ? parsed : null;
}
export function PolicyForm({ policyId, onCreated, onCheckHistory }: Props) {
  const prefix = useId();
  const [name, setName] = useState('');
  const [values, setValues] = useState<PolicyRuleFormValues>({
    max_critical: '0',
    max_high: '5',
    require_sbom: true,
    unknown_severity_action: '',
  });
  const [errors, setErrors] = useState<Errors>({});
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState<number | null>(null);
  const request = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      request.current?.abort();
      request.current = null;
    },
    [],
  );
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (request.current) return;
    const local: Errors = {};
    const trimmedName = name.trim();
    if (!policyId && (!trimmedName || [...trimmedName].length > 100))
      local.name = 'Enter a policy name from 1 to 100 characters.';
    const critical = threshold(values.max_critical);
    const high = threshold(values.max_high);
    if (critical === null)
      local.max_critical = 'Enter a whole number from 0 to 2,147,483,647.';
    if (high === null)
      local.max_high = 'Enter a whole number from 0 to 2,147,483,647.';
    if (!values.unknown_severity_action)
      local.unknown_severity_action = 'Choose Fail or Ignore.';
    setErrors(local);
    setError(null);
    setSaved(null);
    if (Object.keys(local).length) return;
    const rules = policyRulesSchema.safeParse({
      ...values,
      max_critical: critical,
      max_high: high,
    });
    if (!rules.success) {
      setError(new ApiError('Check the rule values.', 422));
      return;
    }
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    try {
      const record = policyId
        ? await createPolicyVersion(
            policyId,
            { rules: rules.data },
            controller.signal,
          )
        : await createPolicy(
            { name: trimmedName, rules: rules.data },
            controller.signal,
          );
      if (controller.signal.aborted || request.current !== controller) return;
      setSaved(record.version_number);
      onCreated(record);
    } catch (cause) {
      if (controller.signal.aborted || request.current !== controller) return;
      const failure =
        cause instanceof ApiError
          ? cause
          : new ApiError('Could not confirm the saved policy.');
      if (!policyId && failure.status === 409) {
        const message =
          'A policy with this name already exists. Choose another name.';
        setErrors({ name: message });
        setError(new ApiError(message, 409));
      } else {
        const fields: Errors = {};
        for (const field of failure.fields) {
          const name = field.field.replace(/^rules\./, '');
          if (
            name === 'name' ||
            name === 'max_critical' ||
            name === 'max_high' ||
            name === 'require_sbom' ||
            name === 'unknown_severity_action'
          )
            fields[name] =
              'The service rejected this value. Check it and try again.';
        }
        setErrors(fields);
        setError(failure);
      }
    } finally {
      if (request.current === controller) {
        request.current = null;
        if (!controller.signal.aborted) setBusy(false);
      }
    }
  }
  const uncertain = error && (error.status === null || error.status >= 500);
  return (
    <form
      className="policy-form"
      aria-label={policyId ? 'Create a policy version' : 'Create a policy'}
      noValidate
      onSubmit={(event) => {
        void submit(event);
      }}
    >
      <h2>{policyId ? 'Create new version' : 'Create a policy'}</h2>
      <p className="field-help">
        {policyId
          ? 'Save a separate set of rules. Earlier versions and their evaluation history remain unchanged. These fields are defaults for a new version, not an edit of saved rules.'
          : 'Choose a unique name. Creating a policy saves its first immutable rule version.'}
      </p>
      {!policyId && (
        <div className="field-group policy-name">
          <label htmlFor={`${prefix}-name`}>Policy name</label>
          <input
            id={`${prefix}-name`}
            name="name"
            value={name}
            disabled={busy}
            aria-invalid={!!errors.name || undefined}
            aria-describedby={`${prefix}-name-help${errors.name ? ` ${prefix}-name-error` : ''}`}
            onChange={(event) => setName(event.target.value)}
          />
          <p className="field-help" id={`${prefix}-name-help`}>
            1–100 characters after trimming surrounding spaces.
          </p>
          {errors.name && (
            <p className="field-error" id={`${prefix}-name-error`}>
              {errors.name}
            </p>
          )}
        </div>
      )}
      <RuleFields
        prefix={prefix}
        values={values}
        errors={errors}
        disabled={busy}
        onChange={setValues}
      />
      <button type="submit" className="button-primary" disabled={busy}>
        {busy ? 'Saving…' : policyId ? 'Create new version' : 'Create policy'}
      </button>
      {Object.keys(errors).length > 0 && !error && (
        <p role="alert" className="inline-error">
          Check the highlighted fields before saving.
        </p>
      )}
      {error && (
        <div role="alert" className="inline-error">
          <p>{error.message}</p>
          {uncertain && (
            <p>
              The request may have been saved. Check saved policies and versions
              before submitting again.
            </p>
          )}
          {uncertain && onCheckHistory && (
            <button
              type="button"
              className="button-secondary"
              onClick={onCheckHistory}
            >
              Check saved policies and versions
            </button>
          )}
        </div>
      )}
      {saved !== null && (
        <p role="status">
          Version {saved} was saved. Its record is shown in version history.
        </p>
      )}
    </form>
  );
}
