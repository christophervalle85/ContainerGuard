import { z } from 'zod';

export interface FieldError {
  field: string;
  message: string;
}
type ErrorKind =
  'http' | 'network' | 'timeout' | 'invalid_response' | 'invalid_request';
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number | null = null,
    public readonly fields: FieldError[] = [],
    public readonly kind: ErrorKind = 'http',
  ) {
    super(message);
    this.name = 'ApiError';
  }
}
const errorMessages: Record<number, string> = {
  404: 'The requested record or artifact was not found.',
  409: 'This request conflicts with the current record. Check its status and try again.',
  422: 'Check the request fields and try again.',
  429: 'The scan queue is full. Try again shortly.',
  502: 'The service is temporarily unavailable. Try again later.',
  503: 'The service is temporarily unavailable. Try again later.',
  504: 'The service is temporarily unavailable. Try again later.',
};
const validationSchema = z.object({
  detail: z.array(
    z.object({ loc: z.array(z.union([z.string(), z.number()])) }),
  ),
});
function invalidResponse(): ApiError {
  return new ApiError(
    'The service returned an unexpected response.',
    null,
    [],
    'invalid_response',
  );
}
function apiPath(path: string): string {
  const normalized = new URL(path, 'http://containerguard.invalid');
  if (
    !path.startsWith('/api/v1/') ||
    normalized.origin !== 'http://containerguard.invalid' ||
    !normalized.pathname.startsWith('/api/v1/') ||
    /[\\#]/.test(path)
  ) {
    throw new ApiError(
      'Invalid API request path.',
      null,
      [],
      'invalid_request',
    );
  }
  return path;
}
function isJson(response: Response): boolean {
  return /^application\/json(?:;|$)/i.test(
    response.headers.get('Content-Type') || '',
  );
}
async function httpError(response: Response): Promise<ApiError> {
  let fields: FieldError[] = [];
  if (response.status === 422 && isJson(response)) {
    const parsed = validationSchema.safeParse(
      await response.json().catch(() => null),
    );
    if (parsed.success)
      fields = parsed.data.detail.map((issue) => ({
        field: issue.loc
          .filter(
            (part) => part !== 'body' && part !== 'query' && part !== 'path',
          )
          .join('.')
          .slice(0, 100),
        message: 'Invalid value.',
      }));
  }
  return new ApiError(
    errorMessages[response.status] || 'The request could not be completed.',
    response.status,
    fields,
  );
}

async function request<T>(
  path: string,
  options: RequestInit,
  read: (response: Response) => Promise<T>,
): Promise<T> {
  const url = apiPath(path);
  const caller = options.signal;
  if (caller?.aborted)
    throw new DOMException('Request cancelled', 'AbortError');
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort();
  caller?.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, 15000);
  try {
    const headers = new Headers(options.headers);
    headers.set('Accept', 'application/json');
    if (options.body !== undefined && options.body !== null)
      headers.set('Content-Type', 'application/json');
    const response = await fetch(url, {
      ...options,
      headers,
      signal: controller.signal,
      credentials: 'same-origin',
      redirect: 'error',
    });
    if (!response.ok) throw await httpError(response);
    if (!isJson(response)) throw invalidResponse();
    return await read(response);
  } catch (error) {
    if (caller?.aborted)
      throw new DOMException('Request cancelled', 'AbortError');
    if (timedOut)
      throw new ApiError(
        'The request timed out. Check the record before submitting again.',
        null,
        [],
        'timeout',
      );
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      'Could not reach the service. Check your connection.',
      null,
      [],
      'network',
    );
  } finally {
    clearTimeout(timer);
    caller?.removeEventListener('abort', cancel);
  }
}

// Generic results require a runtime decoder; unvalidated JSON remains unknown.
export function requestJson(
  path: string,
  options?: RequestInit,
): Promise<unknown>;
export function requestJson<T>(
  path: string,
  options: RequestInit,
  decode: (value: unknown) => T,
): Promise<T>;
export function requestJson<T>(
  path: string,
  options: RequestInit = {},
  decode?: (value: unknown) => T,
): Promise<unknown | T> {
  return request(path, options, async (response) => {
    let value: unknown;
    try {
      value = await response.json();
    } catch {
      throw invalidResponse();
    }
    return decode ? decode(value) : value;
  });
}
export function parseResponse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw invalidResponse();
  return result.data;
}
export function requestDownload(
  path: string,
  options: RequestInit = {},
): Promise<Blob> {
  return request(path, options, async (response) => {
    const blob = await response.blob();
    if (blob.size === 0) throw invalidResponse();
    return blob;
  });
}
export function pageQuery({
  limit,
  offset,
}: {
  limit: number;
  offset: number;
}): string {
  return new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  }).toString();
}
