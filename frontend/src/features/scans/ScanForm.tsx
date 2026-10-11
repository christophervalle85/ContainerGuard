import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { ApiError } from '../../api/client';
import { submitScan } from '../../api/scans';

export function ScanForm({
  onHistoryRefresh,
}: {
  onHistoryRefresh: () => void;
}) {
  const [reference, setReference] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const active = useRef<AbortController | null>(null);
  const navigate = useNavigate();
  useEffect(
    () => () => {
      active.current?.abort();
    },
    [],
  );
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (active.current) return;
    const image = reference.trim();
    if (!image) {
      setError(new ApiError('Enter an image reference.', 422));
      return;
    }
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError(null);
    try {
      const accepted = await submitScan(
        { image_reference: image },
        controller.signal,
      );
      if (controller.signal.aborted || active.current !== controller) return;
      navigate(`/scans/${encodeURIComponent(accepted.scan_id)}`);
    } catch (cause) {
      if (controller.signal.aborted || active.current !== controller) return;
      setError(
        cause instanceof ApiError
          ? cause
          : new ApiError('Could not confirm the submission.'),
      );
    } finally {
      if (active.current === controller) {
        active.current = null;
        if (!controller.signal.aborted) setBusy(false);
      }
    }
  }
  const invalid = error?.status === 422;
  const uncertain = error !== null && !invalid;
  return (
    <form
      className="scan-form"
      aria-label="Submit an image scan"
      onSubmit={submit}
    >
      <h2>Scan an image</h2>
      <p id="image-scope" className="field-help">
        Public Docker Hub images only. Scans use linux/amd64; submitted images
        are never run.
      </p>
      <div className="scan-form-row">
        <div className="field-group">
          <label htmlFor="image-reference">Image reference</label>
          <input
            id="image-reference"
            name="image_reference"
            type="text"
            value={reference}
            required
            maxLength={512}
            placeholder="docker.io/library/alpine:3.20.0"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            disabled={busy}
            aria-invalid={invalid || undefined}
            aria-describedby={
              invalid ? 'image-scope submission-error' : 'image-scope'
            }
            onChange={(event) => {
              setReference(event.target.value);
              setError(null);
            }}
          />
        </div>
        <button className="button-primary" type="submit" disabled={busy}>
          {busy ? 'Submitting…' : 'Submit scan'}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert" id="submission-error">
          <p>{error.message}</p>
          {uncertain && (
            <p>
              The request may have been saved. Check scan history before
              submitting again.{' '}
              <a href="#scan-history" onClick={onHistoryRefresh}>
                Check scan history
              </a>
            </p>
          )}
        </div>
      )}
    </form>
  );
}
