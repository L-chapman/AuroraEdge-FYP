FROM node:24-alpine AS frontend-dependencies

WORKDIR /frontend

# Copy dependency manifests first so Docker can reuse the npm install layer.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci


FROM frontend-dependencies AS frontend-build

COPY frontend/ ./
RUN npm run build


FROM frontend-dependencies AS frontend-test

COPY frontend/ ./
RUN npm run typecheck \
    && npm run lint \
    && npm run test:coverage \
    && npm run build


FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    MPLCONFIGDIR=/tmp/matplotlib \
    NORTHFLUX_ENV=production

WORKDIR /app

RUN groupadd --system northflux \
    && useradd --system --gid northflux --home-dir /app northflux

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY --from=frontend-build --chown=northflux:northflux /frontend/dist ./frontend/dist

RUN mkdir -p /app/state /app/reports/indexed /app/reports/archive /app/logs /tmp/matplotlib \
    && chown -R northflux:northflux /app/state /app/reports /app/logs /tmp/matplotlib

USER northflux

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/ready', timeout=3).read()"

# Keep one worker: the application owns one SQLite connection and one scheduler.
CMD ["python", "-m", "uvicorn", "app.dashboard:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]

FROM runtime AS test

USER root
ENV NORTHFLUX_ENV=development
# Tests cover the source launchers and documentation links as well as the API.
# .dockerignore excludes local data, secrets and generated dependencies. Only
# this test stage receives the review files; production still derives from runtime.
COPY . ./
RUN python -m pip install --no-cache-dir -r requirements-dev.txt \
    && chown -R northflux:northflux /app
USER northflux
RUN python -m pytest -q \
    && python verify_system.py --offline

FROM runtime AS production
