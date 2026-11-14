"""The live stage: real Claude agents in a simulated company, with Segurai deciding.

    segurai stage

Made for people who don't read code. Pick a scene, press "Run it live", and
watch a person's request travel through two AI agents to a CRM, with every
step checked by Segurai. Runs are recorded, so they can be played back later
without the internet or an API key. See show.py for how a run works and
office.py for the simulated company.
"""

from .show import SCENES, Stage, StageServer, serve_stage

__all__ = ["SCENES", "Stage", "StageServer", "serve_stage"]
