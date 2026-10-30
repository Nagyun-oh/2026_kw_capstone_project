import { useEffect, useRef } from 'react';

function BlacklistDeleteModal({
  entry,
  busy,
  error,
  onClose,
  onConfirm,
}) {
  const dialogRef = useRef(null);
  const cancelButtonRef = useRef(null);
  const isOpen = entry != null;

  useEffect(() => {
    if (!isOpen) return;

    const dialog = dialogRef.current;
    if (!dialog) return;

    const previousOverflow = document.body.style.overflow;

    if (!dialog.open) {
      dialog.showModal();
    }

    document.body.style.overflow = 'hidden';
    cancelButtonRef.current?.focus();

    return () => {
      if (dialog.open) {
        dialog.close();
      }

      document.body.style.overflow = previousOverflow;
    };
  }, [isOpen]);

  const handleCancel = event => {
    event.preventDefault();

    if (!busy) {
      onClose();
    }
  };

  return (
    <dialog
      ref={dialogRef}
      className="blacklist-confirm"
      aria-labelledby="blacklist-delete-title"
      aria-describedby="blacklist-delete-description"
      aria-busy={busy}
      onCancel={handleCancel}
    >
      <div className="blacklist-confirm__content">
        <header className="blacklist-confirm__header">
          <div>
            <p className="log-detail-eyebrow">BLACKLIST MANAGEMENT</p>
            <h2 id="blacklist-delete-title">블랙리스트 삭제</h2>
          </div>

          <button
            type="button"
            className="log-detail-close"
            aria-label="삭제 확인창 닫기"
            disabled={busy}
            onClick={onClose}
          >
            ×
          </button>
        </header>

        <div className="blacklist-confirm__body">
          <p id="blacklist-delete-description">
            아래 IP를 블랙리스트에서 삭제하시겠습니까?
          </p>

          <div className="blacklist-confirm__ip">
            {entry?.ipAddress}
          </div>

          <p className="blacklist-confirm__note">
            원본 로그와 위협 탐지 기록은 유지됩니다.
            새로운 위협이 탐지되면 다시 등록될 수 있습니다.
          </p>

          {error && (
            <p className="blacklist-confirm__error" role="alert">
              {error}
            </p>
          )}
        </div>

        <footer className="blacklist-confirm__footer">
          <button
            ref={cancelButtonRef}
            type="button"
            className="dashboard-button dashboard-button--secondary"
            disabled={busy}
            onClick={onClose}
          >
            취소
          </button>

          <button
            type="button"
            className="dashboard-button dashboard-button--danger"
            disabled={busy || !entry}
            onClick={onConfirm}
          >
            {busy ? '삭제 중…' : '삭제하기'}
          </button>
        </footer>
      </div>
    </dialog>
  );
}

export default BlacklistDeleteModal;