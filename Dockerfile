FROM debian:bullseye-slim

RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        python3-distutils \
        python3-minimal \
        python3-unbound \
        unbound \
    && apt-get clean \
    && find /var/lib/apt/lists -type f -delete \
    && find /var/cache/debconf -type f -name '*-old' -delete \
    && :
