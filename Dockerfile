FROM eclipse-temurin:21-jre-noble

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

# The default process is root. `docker run -v "$PWD:/work" -w /work` writes
# the report as root because the mount is owned by the host user. A fixed
# USER would fail that command. The image still has a `checkstead` user
# (uid 10001). Run as the host user when the mount should stay owned by
# that user:
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work ...
# The entrypoint gives a non-root uid a writable HOME and cache. The engine
# and the virtualenv are world-executable. Do not add --privileged.

COPY pyproject.toml README.md /opt/checkstead-src/
COPY src /opt/checkstead-src/src
RUN python3 -m venv /opt/checkstead-venv \
    && /opt/checkstead-venv/bin/pip install --no-cache-dir /opt/checkstead-src \
    && ln -sf /opt/checkstead-venv/bin/checkstead /usr/local/bin/checkstead

COPY scripts/docker-entrypoint.sh /usr/local/bin/checkstead-entry
COPY checkstead.yml /etc/checkstead/checkstead.yml
RUN chmod 0755 /usr/local/bin/checkstead-entry \
    && chmod -R a+rX /opt/dependency-check /opt/checkstead-venv \
    && groupadd --system --gid 10001 checkstead \
    && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/checkstead --create-home checkstead \
    && mkdir -p /var/cache/checkstead \
    && chown checkstead:checkstead /var/cache/checkstead \
    && chmod 0755 /var/cache/checkstead

ENV CHECKSTEAD_ENGINE=/opt/dependency-check/bin/dependency-check.sh
ENTRYPOINT ["/usr/local/bin/checkstead-entry"]
