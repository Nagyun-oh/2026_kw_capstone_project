"""EC2 관리자 폼 자동 로그인. 자격 증명은 숨김 입력 후 메모리에만 둔다."""
from dataclasses import dataclass,field
import getpass
import sys
import warnings
from urllib.parse import urlsplit

from e2e_environment import select_environment


@dataclass(repr=False)
class Credentials:
    username:str=field(repr=False)
    password:str=field(repr=False)
    db_password:str|None=field(default=None,repr=False)

    def __repr__(self): return '<Credentials REDACTED>'

    def clear(self):
        self.username=self.password=''
        self.db_password=None


def read_credentials(include_db=True):
    if not sys.stdin.isatty(): raise RuntimeError('숨김 입력은 직접 연 PowerShell에서 실행해야 합니다.')
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        username=getpass.getpass('EC2 관리자 ID (숨김 입력): ')
        password=getpass.getpass('EC2 관리자 비밀번호 (숨김 입력): ')
        db_password=getpass.getpass('기존 MySQL root 비밀번호 (숨김 입력): ') if include_db else None
    if not username or not password or any('\x00' in v or '\n' in v or '\r' in v for v in (username,password,db_password or '')):
        raise RuntimeError('입력 형식을 확인해주세요. 값은 저장하지 않았습니다.')
    return Credentials(username,password,db_password)


async def login_ec2(page,credentials):
    wanted=urlsplit(select_environment('ec2').dashboard_url)
    actual=urlsplit(page.url)
    if (actual.scheme,actual.hostname,actual.port)!=(wanted.scheme,wanted.hostname,wanted.port):
        raise RuntimeError('EC2_ADMIN_ORIGIN_MISMATCH')
    try:
        if await page.evaluate('window.__dgReady === true'): return
        await page.locator('input[name="username"]').fill(credentials.username,timeout=10000)
        await page.locator('input[name="password"]').fill(credentials.password,timeout=10000)
        await page.get_by_role('button',name='로그인',exact=True).click(timeout=10000)
        await page.wait_for_function('window.__dgReady === true || !!document.querySelector(".login-message--error")',timeout=30000)
        if not await page.evaluate('window.__dgReady === true'): raise RuntimeError()
    except Exception:
        raise RuntimeError('EC2_ADMIN_LOGIN_OR_STOMP_FAILED_REDACTED') from None
