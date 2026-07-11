import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from app.main import get_settings, update_settings, SettingsUpdateRequest
from app.config import settings

@pytest.mark.anyio
async def test_settings_api_directly():
    # Retrieve current values first
    old_id = settings.FALCON_CLIENT_ID
    old_secret = settings.FALCON_CLIENT_SECRET
    old_url = settings.FALCON_BASE_URL

    test_id = "test-new-client-id"
    test_secret = "test-new-client-secret"
    test_url = "https://api.test.crowdstrike.com"

    try:
        # Test get_settings
        res_get = await get_settings()
        assert res_get["client_id"] == old_id
        assert res_get["client_secret"] == old_secret
        assert res_get["base_url"] == old_url

        # Test update_settings
        req = SettingsUpdateRequest(
            client_id=test_id,
            client_secret=test_secret,
            base_url=test_url
        )
        res_post = await update_settings(req)
        assert res_post["status"] == "success"

        # Verify in-memory update
        assert settings.FALCON_CLIENT_ID == test_id
        assert settings.FALCON_CLIENT_SECRET == test_secret
        assert settings.FALCON_BASE_URL == test_url

        # Verify GET reflects new values
        res_get_new = await get_settings()
        assert res_get_new["client_id"] == test_id
        assert res_get_new["client_secret"] == test_secret
        assert res_get_new["base_url"] == test_url

    finally:
        # Restore old values to avoid polluting the .env file permanently
        req_restore = SettingsUpdateRequest(
            client_id=old_id,
            client_secret=old_secret,
            base_url=old_url
        )
        await update_settings(req_restore)
