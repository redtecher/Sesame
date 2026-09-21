import json
import re

from sesame.domain.surface import BinaryAnalysisResult
from sesame.utils.logger import get_logger

logger = get_logger(__name__)

_AUTH_STRING_PATTERNS = re.compile(
    r"login|auth|passw|sessi|cookie|nvram|token|admin|"
    r"loginAuth|validity|check.*pass|user.*name|login_flag",
    re.IGNORECASE,
)

_AUTH_FUNC_PATTERNS = re.compile(
    r"login|auth|check|verify|valid|session|loginAuth|"
    r"Validity|apCheck|verifyAuth|checkLogin|doLogin",
    re.IGNORECASE,
)

_KEY_IMPORT_PATTERNS = re.compile(
    r"strcmp|strncmp|memcmp|nvram_get|nvram_set|nvram_bufget|"
    r"websCompare|apCheck|cgibin|fopen|system",
    re.IGNORECASE,
)


class BinaryAnalyzer:
    def __init__(self):
        self._r2pipe = None
        try:
            import r2pipe  # noqa: F401

            self._r2pipe = r2pipe
        except ImportError:
            logger.warning("r2pipe not available, binary analysis disabled")

    def is_available(self) -> bool:
        return self._r2pipe is not None

    def analyze(self, binary_path: str) -> BinaryAnalysisResult:
        if not self.is_available():
            return BinaryAnalysisResult(path=binary_path, name=binary_path.rsplit("/", 1)[-1])

        name = binary_path.rsplit("/", 1)[-1]
        try:
            r2 = self._r2pipe.open(binary_path, flags=["-2"])
            try:
                return self._run_analysis(r2, binary_path, name)
            finally:
                r2.quit()
        except Exception as e:
            logger.warning(f"r2 analysis failed for {binary_path}: {e}")
            return BinaryAnalysisResult(path=binary_path, name=name)

    def analyze_surface(self, surface, _settings=None) -> list[BinaryAnalysisResult]:
        results = []
        binaries = surface.web_binaries[:3] + surface.cgi_binaries[:5]
        for b in binaries:
            result = self.analyze(b.path)
            b.analysis = result
            b.arch = result.arch
            results.append(result)
        return results

    def _run_analysis(self, r2, binary_path: str, name: str) -> BinaryAnalysisResult:
        arch, bits, endian, stripped = self._binary_info(r2)
        auth_strings = self._auth_strings(r2)
        r2.cmd("e anal.timeout=30")
        r2.cmd("aaa")
        auth_functions = self._auth_functions(r2)
        key_imports = self._key_imports(r2)
        auth_decompilation = self._auth_decompilation(r2, auth_functions)

        return BinaryAnalysisResult(
            path=binary_path,
            name=name,
            arch=arch,
            bits=bits,
            endian=endian,
            stripped=stripped,
            auth_strings=auth_strings[:30],
            auth_functions=auth_functions[:20],
            key_imports=key_imports[:20],
            auth_decompilation=auth_decompilation[:2000],
        )

    def _binary_info(self, r2) -> tuple[str, int, str, bool]:
        try:
            info_raw = r2.cmd("iIj")
            info = json.loads(info_raw)
            arch = info.get("arch", "unknown")
            bits = info.get("bits", 0)
            endian = "big" if info.get("endian", "") == "big" else "little"
            stripped = "true" in str(info.get("stripped", True)).lower()
            return arch, bits, endian, stripped
        except Exception:
            return "unknown", 0, "unknown", True

    def _auth_strings(self, r2) -> list[str]:
        try:
            raw = r2.cmd("iz")
        except Exception:
            return []
        results = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("nth"):
                continue
            # iz output: idx paddr vaddr len size section type string_value
            # string_value starts after the type field (ascii/wide/utf8) at index 7
            parts = line.split()
            if len(parts) < 8:
                continue
            s = " ".join(parts[7:])
            if _AUTH_STRING_PATTERNS.search(s) and len(s) > 2:
                results.append(s)
        return results

    def _auth_functions(self, r2) -> list[str]:
        try:
            raw = r2.cmd("afl")
        except Exception:
            return []
        results = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                func_name = parts[-1]
                if _AUTH_FUNC_PATTERNS.search(func_name):
                    results.append(func_name)
        return results

    def _key_imports(self, r2) -> list[str]:
        try:
            raw = r2.cmd("ii")
        except Exception:
            return []
        results = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 1:
                name = parts[-1]
                if _KEY_IMPORT_PATTERNS.search(name):
                    results.append(name)
        return results

    def _auth_decompilation(self, r2, auth_functions: list[str]) -> str:
        if not auth_functions:
            return ""
        parts = []
        for func in auth_functions[:2]:
            try:
                decomp = r2.cmd(f"pdc @ {func}")
                if decomp and len(decomp.strip()) > 10:
                    truncated = decomp.strip()[:500]
                    parts.append(f"--- {func} ---\n{truncated}")
            except Exception:
                pass
        return "\n\n".join(parts)
