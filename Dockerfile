FROM eclipse-temurin:24-jre-noble

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
        curl \
        unzip \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

COPY engine.version /tmp/engine.version
COPY scripts/install-engine.sh /tmp/install-engine.sh
COPY scripts/keys/dependency-check-release.asc /tmp/dependency-check-release.asc
COPY src/checkstead/archive.py /tmp/archive.py
RUN ENGINE_VERSION_FILE=/tmp/engine.version \
    ENGINE_PUBLIC_KEY=/tmp/dependency-check-release.asc \
    CHECKSTEAD_ARCHIVE=/tmp/archive.py \
    bash /tmp/install-engine.sh /opt/dependency-check \
    && rm -f /tmp/install-engine.sh /tmp/engine.version /tmp/archive.py /tmp/dependency-check-release.asc \
    && apt-get purge -y gnupg \
    && rm -rf /var/lib/apt/lists/*

# The scanner process stays root. The documented command is
# docker run -v "$PWD:/work" -w /work, and that mount is owned by the host
# user. A fixed non-root USER fails that command when the mount is not
# writable by the image user. See docs/security/threat-model.md.

COPY pyproject.toml README.md /opt/checkstead-src/
COPY src /opt/checkstead-src/src
RUN python3 -m venv /opt/checkstead-venv \
    && /opt/checkstead-venv/bin/pip install --no-cache-dir /opt/checkstead-src \
    && ln -sf /opt/checkstead-venv/bin/checkstead /usr/local/bin/checkstead

COPY scripts/docker-entrypoint.sh /usr/local/bin/checkstead-entry
COPY checkstead.yml /etc/checkstead/checkstead.yml
RUN chmod 0755 /usr/local/bin/checkstead-entry

ENV CHECKSTEAD_ENGINE=/opt/dependency-check/bin/dependency-check.sh
ENTRYPOINT ["/usr/local/bin/checkstead-entry"]
