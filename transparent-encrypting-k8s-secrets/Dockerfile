FROM registry.access.redhat.com/ubi8/ubi:8.6 AS builder

RUN export HELM_VERSION=3.9.4 && \
    curl -L -o /tmp/helm-v${HELM_VERSION}-linux-amd64.tar.gz https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz && \
    tar -C /tmp -xzf /tmp/helm-v${HELM_VERSION}-linux-amd64.tar.gz && \
    /tmp/linux-amd64/helm version

# Runnable image
FROM registry.redhat.io/openshift4/ose-cli:v4.10.0

RUN mkdir -p /home/appuser && \
    useradd -u 1001 -r -g 0 -d /home/appuser -s /sbin/nologin -c "Default Application User" default && \
    rpm -i http://ccrypt.sourceforge.net/download/1.11/ccrypt-1.11-1.x86_64.rpm

USER 1001

COPY --from=builder /tmp/linux-amd64/helm /usr/local/bin/helm
RUN helm version

CMD ["helm", "version"]
