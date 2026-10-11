interface PaginationProps {
  limit: number;
  offset: number;
  total: number;
  onPageChange: (offset: number) => void;
}
export function Pagination({
  limit,
  offset,
  total,
  onPageChange,
}: PaginationProps) {
  const summary =
    total === 0
      ? '0 results'
      : offset >= total
        ? `${total} results total`
        : `${offset + 1}–${Math.min(offset + limit, total)} of ${total}`;
  return (
    <nav className="pagination" aria-label="Pagination">
      <span className="pagination-summary">{summary}</span>
      <div className="pagination-actions">
        <button
          type="button"
          className="button-secondary"
          disabled={offset === 0}
          onClick={() => onPageChange(Math.max(0, offset - limit))}
        >
          Previous page
        </button>
        <button
          type="button"
          className="button-secondary"
          disabled={offset + limit >= total}
          onClick={() => onPageChange(offset + limit)}
        >
          Next page
        </button>
      </div>
    </nav>
  );
}
