# CAVR behaviour sandbox image, asent-cavr-sandbox:local (docs/cavr-m2-plan.md PR 3, decisions Q5-Q7).
# Separate from SATRA's asent-sandbox:local. Build it only with docker/cavr-sandbox/build.sh, which labels the image
# with this file's SHA-256 and records the image ID that every CAVR run checks first.
#
# Base pinned by digest (python:3.12-slim, Debian 13 trixie, linux/amd64 + arm64 index, pulled 2026-11-05).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# strace: the only process that runs as container root (Q5). libfaketime: time triggers in Phase 3 (Q7).
# User cavr (10001): every package process runs as this user, started by `strace -u cavr`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace libfaketime \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 cavr \
 && useradd -u 10001 -g 10001 -M -d /nonexistent -s /usr/sbin/nologin cavr \
 && mkdir -p /opt/cavr /pkg /site

# No setuid / setgid file and no file capability anywhere (PR 7): strace holds DAC_READ_SEARCH (to read
# /proc/<pid>/fd for -y), and with these bits gone nothing a package process can exec could ever gain a privilege,
# on top of no-new-privileges. tests/test_cavr_sandbox_image.py checks the built image.
RUN find / -xdev -type f -perm /6000 -exec chmod ug-s {} + \
 && test -z "$(find / -xdev -type f -perm /6000)"

# pip is the base image's own (pinned by the digest above). The sandbox's install command replaces pip's
# User-Agent builder (sandbox_observe.PIP_CODE), which is written for this version: the build fails if it differs.
ARG PIP_VERSION=25.0.1
RUN test "$(python -m pip --version | cut -d' ' -f2)" = "$PIP_VERSION"
LABEL org.asent.cavr.pip-version="25.0.1"

# No ENTRYPOINT: the runner passes the whole command. The harness is mounted read-only at run time.
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_NO_INPUT=1
WORKDIR /tmp
