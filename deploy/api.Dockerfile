# CyberGuard backend for the cloud server (9 Nov 2026). Built by deploy/docker-compose.cloud.yml (context: backend/).
# The trained models are NOT in this image: they are uploaded once and mounted (see docs/DEPLOY_CLOUD.md).
# Python 3.13 = the version the backend tests passed with on Linux; constraints-cloud.txt pins every package to the
# tested version (all of them install as ready-made Linux wheels, nothing is compiled).
FROM python:3.13-slim

WORKDIR /app

# libgomp1: LightGBM (the EMBER2024 malware model) needs OpenMP - the only system library the packages need that the
# slim image does not have. git: requirements.txt installs one pinned commit of oscrypto from GitHub.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-ocr.txt constraints-cloud.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints-cloud.txt
# Screenshot text reading (chat / scans), exactly as on the laptop: WITHOUT dependencies, so pip does not add a second
# OpenCV next to opencv-python-headless (see requirements-ocr.txt)
RUN pip install --no-cache-dir --no-deps -r requirements-ocr.txt -c constraints-cloud.txt

COPY . .

# Runs as an ordinary user, not root: a bug in a file parser can then not take over the container.
RUN useradd --create-home --uid 10001 cyberguard \
    && mkdir -p uploads reports app/ml/models \
    && chown -R cyberguard:cyberguard /app
USER cyberguard

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# FORWARDED_ALLOW_IPS (set in the compose file) lets uvicorn read the visitor's real address from the web server.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-server-header --proxy-headers"]
