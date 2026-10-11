function TablePagination({
  pageInfo,
  itemCount,
  onPageChange,
  label,
}) {
  return (
    <footer className="data-pagination">
      <span>
        현재 페이지 {itemCount.toLocaleString('ko-KR')}건
      </span>

      <nav
        className="data-pagination__controls"
        aria-label={`${label} 페이지`}
      >
        <button
          type="button"
          className="dashboard-button dashboard-button--secondary"
          disabled={pageInfo.number === 0}
          onClick={() => onPageChange(pageInfo.number - 1)}
        >
          이전
        </button>

        <span className="data-pagination__position">
          {pageInfo.totalPages === 0 ? 0 : pageInfo.number + 1}
          {' / '}
          {pageInfo.totalPages}
        </span>

        <button
          type="button"
          className="dashboard-button dashboard-button--secondary"
          disabled={pageInfo.number + 1 >= pageInfo.totalPages}
          onClick={() => onPageChange(pageInfo.number + 1)}
        >
          다음
        </button>
      </nav>
    </footer>
  );
}

export default TablePagination;