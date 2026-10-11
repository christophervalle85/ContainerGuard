/** Mirror the API's supported explicit public Docker Hub tag grammar. */
export function isSupportedImageReference(value: string): boolean {
  const reference = value.trim();
  if (
    reference.length > 512 ||
    !reference.startsWith('docker.io/') ||
    reference.includes('@')
  )
    return false;
  const suffix = reference.slice('docker.io/'.length);
  const separator = suffix.lastIndexOf(':');
  if (separator < 0) return false;
  const rawRepository = suffix.slice(0, separator);
  const repository = rawRepository.includes('/')
    ? rawRepository
    : `library/${rawRepository}`;
  const tag = suffix.slice(separator + 1);
  // Use absolute end assertions: JavaScript $ can also match before a final newline.
  return (
    /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+(?![\s\S])/.test(
      repository,
    ) && /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}(?![\s\S])/.test(tag)
  );
}
