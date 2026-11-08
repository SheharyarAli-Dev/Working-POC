# SATRA runner base image (asent-satra-runner:local): CPython 3.12 and pytest, nothing else.
# Per-project gate images (backend/satra/project_image.py) are built FROM this image and add only
# the CAVR-approved wheels of the project's base-commit lockfile. ASENT's own dependencies are
# deliberately not here (they are in asent-sandbox:local, which gate runs never use).
# Build context: docker/   ->   docker build -t asent-satra-runner:local -f docker/satra-runner.Dockerfile docker
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
COPY satra-runner.requirements.txt /opt/asent/satra-runner.requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all: \
        -r /opt/asent/satra-runner.requirements.txt
ENV PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
WORKDIR /work
