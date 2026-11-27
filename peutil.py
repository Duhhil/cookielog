# peutil.py -- compatibility shim. Implementation lives in cklog/pe.py so the
# same code serves auto.py, pick.py, build.py and the tests.
from cklog.pe import (MZ, PE, _inside, _section_of, find_sentinel, patch_ready,
                      section_of, sections, sha256)

__all__ = ["MZ", "PE", "sections", "find_sentinel", "patch_ready",
           "section_of", "sha256", "_inside", "_section_of"]
