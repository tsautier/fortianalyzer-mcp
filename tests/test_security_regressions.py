"""Regression tests for the security-hardening fixes.

Covers device-credential masking on the device-listing tools and the
adom/device-name and severity/status validation on the mutation tools.

Each fake client mirrors the real FortiAnalyzerClient method signature so a
tool passing a wrong keyword argument fails the test (a plain MagicMock would
silently accept anything).
"""

from __future__ import annotations

from typing import Any

import pytest

import fortianalyzer_mcp.tools.dvm_tools as dvm_tools
import fortianalyzer_mcp.tools.incident_tools as incident_tools
import fortianalyzer_mcp.tools.system_tools as system_tools
from fortianalyzer_mcp.utils.validation import MASK_VALUE

DEVICE_WITH_CREDS = {
    "name": "FGT-01",
    "ip": "192.168.1.1",
    "sn": "FGT60F0000000001",
    "conn_status": 1,
    "adm_usr": "admin",
    "adm_pass": ["ENC", "SH2MPbdXdoo7ekXsbtjm0Ga"],
}


class TestDeviceCredentialSanitization:
    """Regression: device tools returned raw DVMDB objects including adm_pass."""

    async def test_system_list_devices_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def list_devices(
                self, adom: str, fields: list[str] | None = None
            ) -> list[dict[str, Any]]:
                return [dict(DEVICE_WITH_CREDS)]

        monkeypatch.setattr(system_tools, "get_faz_client", lambda: FakeClient())

        result = await system_tools.list_devices(adom="root")

        assert result["status"] == "success"
        device = result["devices"][0]
        assert device["adm_pass"] == MASK_VALUE
        assert device["name"] == "FGT-01"
        assert device["ip"] == "192.168.1.1"

    async def test_system_get_device_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def get_device(self, name: str, adom: str, loadsub: int = 0) -> dict[str, Any]:
                return dict(DEVICE_WITH_CREDS)

        monkeypatch.setattr(system_tools, "get_faz_client", lambda: FakeClient())

        result = await system_tools.get_device(name="FGT-01", adom="root")

        assert result["status"] == "success"
        assert result["device"]["adm_pass"] == MASK_VALUE

    async def test_dvm_search_devices_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def list_devices(
                self, adom: str, filter: list[Any] | None = None
            ) -> list[dict[str, Any]]:
                return [dict(DEVICE_WITH_CREDS)]

        monkeypatch.setattr(dvm_tools, "get_faz_client", lambda: FakeClient())

        result = await dvm_tools.search_devices(adom="root", name_filter="FGT")

        assert result["status"] == "success"
        assert result["devices"][0]["adm_pass"] == MASK_VALUE

    async def test_dvm_get_device_info_masks_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def get_device(self, device: str, adom: str, loadsub: int = 0) -> dict[str, Any]:
                return dict(DEVICE_WITH_CREDS)

        monkeypatch.setattr(dvm_tools, "get_faz_client", lambda: FakeClient())

        result = await dvm_tools.get_device_info(device="FGT-01", adom="root")

        assert result["status"] == "success"
        assert result["device"]["adm_pass"] == MASK_VALUE


class TestIncidentInputValidation:
    """create_incident/update_incident must reject invalid severity/status."""

    async def test_create_incident_rejects_invalid_severity(self) -> None:
        result = await incident_tools.create_incident(name="Test", severity="catastrophic")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_update_incident_rejects_invalid_status(self) -> None:
        result = await incident_tools.update_incident(incident_id="INC-1", status="bogus")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_update_incident_rejects_invalid_severity(self) -> None:
        result = await incident_tools.update_incident(incident_id="INC-1", severity="bogus")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_create_incident_accepts_valid_severity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeClient:
            async def create_incident(self, **kwargs: Any) -> dict[str, Any]:
                return {"id": "INC-9"}

        monkeypatch.setattr(incident_tools, "get_faz_client", lambda: FakeClient())

        result = await incident_tools.create_incident(name="Test", severity="High")
        assert result["status"] == "success"
        assert result["severity"] == "high"


class TestDvmMutationValidation:
    """add/delete device tools must validate adom and device names."""

    async def test_add_device_rejects_bad_adom(self) -> None:
        result = await dvm_tools.add_device(adom="root; rm -rf /", name="FGT-X", ip="10.0.0.1")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]

    async def test_delete_device_rejects_bad_name(self) -> None:
        result = await dvm_tools.delete_device(adom="root", device="x/../../etc")
        assert result["status"] == "error"
        assert "Validation error" in result["message"]
