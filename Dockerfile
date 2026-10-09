FROM eclipse-temurin:21-jre-noble

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
        curl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

COPY engine.version /tmp/engine.version
COPY scripts/install-engine.sh /tmp/install-engine.sh
RUN ENGINE_VERSION_FILE=/tmp/engine.version bash /tmp/install-engine.sh /opt/dependency-check \
    && rm /tmp/install-engine.sh /tmp/engine.version

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
