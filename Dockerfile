# Rebuilding the package is needed to get DoH in the binary, see the following links:
# - https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=973793
# - https://salsa.debian.org/dns-team/unbound/-/merge_requests/14/diffs
FROM debian:bullseye-slim AS builder
RUN set -ex \
    && sed 's/^deb /deb-src /' </etc/apt/sources.list >/etc/apt/sources.list.d/default-src.list \
    && apt-get update \
    && apt-get build-dep -y unbound \
    && apt-get install -y libnghttp2-dev build-essential \
    && cd /root \
    && apt-get source unbound \
    && cd /root/unbound-1.13.0 \
    && sed -i '/libexpat1-dev,/ { p; s/libexpat1-dev/libnghttp2-dev/ }' debian/control \
    && sed -i '/--enable-subnet/ { p; s/enable-subnet/with-libnghttp2/ }' debian/rules \
    && dpkg-buildpackage \
    && cd /root \
    && cp -a \
        $(awk '(/^ [0-9a-f]/ && NF == 3 && length($1) == 64 && $2 > 1) {print $3}' unbound_1.13.0-1_amd64.buildinfo) \
        unbound_1.13.0-1_amd64.buildinfo \
        unbound_1.13.0-1_amd64.changes \
        /opt/ \
    && :

FROM debian:bullseye-slim

COPY --from=builder /opt/ /tmp/deb/

# Pin is needed as (for a reason unknown to me) `apt` decides to upgrade
# unbound from 1.13.0-1 to 1.13.0-1 (sic!) otherwise.
# python3-distutils looks like missing dependency for python3-unbound.
RUN set -ex \
    && cd /tmp/deb \
    && dpkg --unpack \
        libunbound8_1.13.0-1_amd64.deb \
        python3-unbound_1.13.0-1_amd64.deb \
        unbound_1.13.0-1_amd64.deb \
        unbound-anchor_1.13.0-1_amd64.deb \
    && cd - \
    && /bin/echo -ne 'Package: libunbound8 python3-unbound unbound unbound-anchor\nPin: release a=now\nPin-Priority: 900\n' >/etc/apt/preferences.d/50kabysdoh-unbound \
    && apt-get update \
    && apt-get install -y --no-install-recommends --fix-broken \
    && apt-get install -y --no-install-recommends python3-distutils \
    && apt-get clean \
    && find /var/lib/apt/lists -type f -delete \
    && find /var/cache/debconf -type f -name '*-old' -delete \
    && rm -rf /tmp/deb \
    && mkdir /srv/kabysdoh \
    && /usr/lib/unbound/package-helper root_trust_anchor_update \
    && :

COPY kabysdoh.py /opt/kabysdoh.py

# -d - do not fork, -p - create no pidfile
CMD ["/usr/sbin/unbound", "-d", "-p", "-c", "/srv/kabysdoh/unbound.conf"]
