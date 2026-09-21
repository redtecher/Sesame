from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sesame.bootstrap import Settings
from sesame.connectors.http import HttpProbe
from sesame.domain.input import AnalysisInput

if TYPE_CHECKING:
    from sesame.connectors.qemu import QemuConnector
    from sesame.browser.driver import BrowserDriver


@dataclass
class RuntimeBundle:
    input: AnalysisInput
    http: HttpProbe
    qemu: QemuConnector | None = None
    browser: BrowserDriver | None = None


def build_runtime_bundle(
    input_data: AnalysisInput,
    settings: Settings,
    qemu_connector: QemuConnector | None = None,
    browser_driver: BrowserDriver | None = None,
) -> RuntimeBundle:
    http = HttpProbe(base_url=input_data.web_url, timeout=settings.http_timeout)
    return RuntimeBundle(input=input_data, http=http, qemu=qemu_connector, browser=browser_driver)
