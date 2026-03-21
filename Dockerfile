FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY . /cert-issuer
WORKDIR /cert-issuer

RUN pip install --upgrade pip setuptools wheel Cython && \
    pip install /cert-issuer/. && \
    pip install -r /cert-issuer/ethereum_requirements.txt && \
    pip install requests

COPY cert_worker.py /cert_worker.py

CMD ["python", "/cert_worker.py"]
