FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace bash coreutils findutils nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 auditor

WORKDIR /audit

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER auditor

ENTRYPOINT ["/entrypoint.sh"]
