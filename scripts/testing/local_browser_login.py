"""로컬 예비 실험용 실제 로그인 폼 입력. 자격 증명을 저장·출력하지 않는다."""
from urllib.parse import urlsplit


async def login_local(page, username, password, wait_for_function):
    origin = urlsplit(page.url)
    if origin.scheme != 'http' or origin.hostname not in {'localhost', '127.0.0.1'} or origin.port != 3000:
        raise RuntimeError('로컬 관리자 화면 이외의 자동 로그인은 거부합니다.')
    try:
        await page.locator('input[name="username"]').fill(username, timeout=10000)
        await page.locator('input[name="password"]').fill(password, timeout=10000)
        await page.get_by_role('button', name='로그인', exact=True).click(timeout=10000)
        await wait_for_function(page,
            'window.__dgReady === true || !!document.querySelector(".login-message--error")', timeout=30000)
        if not await page.evaluate('window.__dgReady === true'):
            raise RuntimeError('인증 또는 구독 준비 실패')
    except Exception:
        # Playwright의 예외 본문에는 fill 인자가 포함될 수 있으므로 전파하지 않는다.
        raise RuntimeError('로컬 자동 로그인 또는 실제 STOMP 연결 준비 실패(세부 비공개)') from None
