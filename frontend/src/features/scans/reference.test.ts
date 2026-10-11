import { describe, expect, it } from 'vitest';
import { isSupportedImageReference } from './reference';

describe('supported image references', () => {
  it.each([
    'docker.io/library/alpine:3.20',
    'docker.io/alpine:tag',
    '  docker.io/org/image:TAG_1  ',
  ])('accepts %s', (value) => {
    expect(isSupportedImageReference(value)).toBe(true);
  });
  it.each([
    'ghcr.io/org/image:tag',
    'https://docker.io/library/alpine:tag',
    'docker.io/user:password@host:tag',
    'docker.io/library/alpine',
    'docker.io/library/../alpine:tag',
    'docker.io/library/alpine:bad\ntag',
    'docker.io/library/alpine@sha256:' + 'a'.repeat(64),
    'docker.io/library/alpine:' + 'a'.repeat(129),
    'docker.io/' + 'a'.repeat(500) + ':tag',
  ])('rejects %s', (value) => {
    expect(isSupportedImageReference(value)).toBe(false);
  });
});
