"""`python -m backend.project_config --write docs` regenerates the committed .asent/ JSON Schemas."""
from backend.project_config.schema import main

raise SystemExit(main())
