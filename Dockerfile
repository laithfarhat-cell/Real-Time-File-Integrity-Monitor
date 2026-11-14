FROM python:3.11-slim

LABEL maintainer="Security Engineering Team" \
      description="Production-grade Real-Time File Integrity Monitor (HIDS)"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/fim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/fim /var/log/fim /host

COPY requirements.txt /opt/fim/requirements.txt
RUN pip install --no-cache-dir -r /opt/fim/requirements.txt

COPY core /opt/fim/core
COPY notifiers /opt/fim/notifiers
COPY main.py /opt/fim/main.py
COPY config.yaml /opt/fim/config.yaml

RUN chmod 0755 /opt/fim/main.py

VOLUME ["/var/lib/fim", "/var/log/fim"]

ENTRYPOINT ["python", "/opt/fim/main.py"]
CMD [ \
    "--config", "/opt/fim/config.yaml", \
    "--db", "/var/lib/fim/baseline.db", \
    "--alerts-file", "/var/log/fim/fim_alerts.json", \
    "--audit-on-start", \
    "--monitor" \
]
