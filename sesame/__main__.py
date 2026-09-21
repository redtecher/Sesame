import os

os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("CREWAI_TELEMETRY_OPT_OUT", "true")

from sesame.cli import app

app()
