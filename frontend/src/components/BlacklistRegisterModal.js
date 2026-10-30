import { useEffect, useRef, useState } from 'react';

function BlacklistRegisterModal({
  busy,
  error,
  onClose,
  onConfirm,
}) {

  // 상태와 ref
  const dialogRef = useRef(null);
  const ipInputRef = useRef(null);

  const [form, setForm] = useState({
    ipAddress: '',
    reason: '',
    dangerLevel: '4',
  });

  // useEffect(마운트/언마운트 처리)
  useEffect(() => {
    const dialog = dialogRef.current;
    const previousFocus = document.activeElement;
    const previousOverflow = document.body.style.overflow;

    if (!dialog.open) {
      dialog.showModal();
    }

    document.body.style.overflow = 'hidden';
    ipInputRef.current?.focus();

    return () => {
      if (dialog.open) {
        dialog.close();
      }

      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, []);

  // 이벤트 핸들러
  function handleChange(event) {
    const { name, value } = event.target;

    setForm(previous => ({
      ...previous,
      [name]: value,
    }));
  }

  function handleSubmit(event) {
    event.preventDefault();

    if (busy) return;

    onConfirm({
      ipAddress: form.ipAddress.trim(),
      reason: form.reason.trim(),
      dangerLevel: Number(form.dangerLevel),
    });
  }

  function handleCancel(event) {
    event.preventDefault();

    if (!busy) {
      onClose();
    }
  }

  // 렌더링 부분
  return (
    <dialog
      ref={dialogRef}
      className="blacklist-confirm"
      aria-labelledby="blacklist-register-title"
      aria-describedby="blacklist-register-description"
      aria-busy={busy}
      onCancel={handleCancel}
    >
      <form onSubmit={handleSubmit}>
        <header className="blacklist-confirm__header">
          <div>
            <p className="log-detail-eyebrow">
              BLACKLIST MANAGEMENT
            </p>
            <h2 id="blacklist-register-title">IP 수동 차단</h2>
          </div>

          <button
            type="button"
            className="log-detail-close"
            aria-label="수동 차단 창 닫기"
            disabled={busy}
            onClick={onClose}
          >
            ×
          </button>
        </header>

        <div className="blacklist-confirm__body">
          <p id="blacklist-register-description">
            관리자가 확인한 IP를 블랙리스트에 등록합니다.
            실제 차단은 WAF 동기화 후 적용됩니다.
          </p>

          <div className="blacklist-register-fields">
            <label className="data-field">
              <span>IP 주소</span>
              <input
                ref={ipInputRef}
                name="ipAddress"
                value={form.ipAddress}
                onChange={handleChange}
                placeholder="예: 203.0.113.20"
                maxLength={45}
                required
                disabled={busy}
                autoComplete="off"
              />
            </label>

            <label className="data-field">
              <span>등록 사유</span>
              <textarea
                name="reason"
                value={form.reason}
                onChange={handleChange}
                placeholder="차단 판단 근거를 입력해주세요."
                maxLength={255}
                rows={3}
                required
                disabled={busy}
              />
            </label>

            <label className="data-field">
              <span>위험도</span>
              <select
                name="dangerLevel"
                value={form.dangerLevel}
                onChange={handleChange}
                disabled={busy}
              >
                <option value="2">MEDIUM</option>
                <option value="3">HIGH</option>
                <option value="4">CRITICAL</option>
              </select>
            </label>
          </div>

          <p className="blacklist-confirm__note">
            이 IP에서 들어오는 이후 JuiceShop 요청에 적용됩니다.
            게이트웨이·신뢰 프록시 등 보호 대상은 차단에서
            제외될 수 있습니다.
          </p>

          {error && (
            <p className="blacklist-confirm__error" role="alert">
              {error}
            </p>
          )}
        </div>

        <footer className="blacklist-confirm__footer">
          <button
            type="button"
            className="dashboard-button dashboard-button--secondary"
            disabled={busy}
            onClick={onClose}
          >
            취소
          </button>

          <button
            type="submit"
            className="dashboard-button dashboard-button--danger"
            disabled={
              busy ||
              !form.ipAddress.trim() ||
              !form.reason.trim()
            }
          >
            {busy ? '등록 중…' : '블랙리스트 등록'}
          </button>
        </footer>
      </form>
    </dialog>
  );
}

export default BlacklistRegisterModal;