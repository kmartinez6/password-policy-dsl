import os
import sys

# Let the test suite run straight out of a checkout, without requiring
# `pip install -e .` first.
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
