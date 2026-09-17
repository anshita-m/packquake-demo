import sys
from pathlib import Path

# Let `import graph_builder` work when running pytest straight from a clean
# checkout, without requiring `pip install -e backend` first.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
