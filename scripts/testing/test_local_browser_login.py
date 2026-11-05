import unittest
from unittest.mock import AsyncMock, Mock
from local_browser_login import login_local


class LocalLoginTests(unittest.IsolatedAsyncioTestCase):
    def page(self, url='http://localhost:3000/'):
        page=Mock(url=url)
        page.locator.return_value.fill=AsyncMock()
        page.get_by_role.return_value.click=AsyncMock()
        page.evaluate=AsyncMock(return_value=True)
        return page

    async def test_uses_actual_form_only_on_local_origin(self):
        page=self.page(); wait=AsyncMock()
        await login_local(page,'fixture-user','fixture-secret',wait)
        self.assertEqual(page.locator.return_value.fill.await_count,2)
        page.get_by_role.return_value.click.assert_awaited_once()
        wait.assert_awaited_once()

    async def test_refuses_external_origin_before_input(self):
        page=self.page('https://example.invalid/'); wait=AsyncMock()
        with self.assertRaises(RuntimeError):
            await login_local(page,'fixture-user','fixture-secret',wait)
        page.locator.assert_not_called()
        wait.assert_not_awaited()

    async def test_redacts_browser_exception(self):
        page=self.page(); page.locator.return_value.fill.side_effect=RuntimeError('fixture-secret')
        with self.assertRaises(RuntimeError) as error:
            await login_local(page,'fixture-user','fixture-secret',AsyncMock())
        self.assertNotIn('fixture-secret',str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    async def test_failed_authentication_never_claims_ready(self):
        page=self.page(); page.evaluate.return_value=False
        with self.assertRaises(RuntimeError):
            await login_local(page,'fixture-user','fixture-secret',AsyncMock())
