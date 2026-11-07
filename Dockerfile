# Stage 1: build the React dashboard
FROM node:20-slim AS web
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Python API that serves the dashboard
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt
COPY . .
COPY --from=web /app/frontend/dist ./frontend/dist
RUN git config --global user.email asent@localhost && git config --global user.name "ASENT"
# The gate CLI: docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" IMAGE asent gate --repository /repo --base B --head H --output-dir /repo/asent-out
RUN install -m 0755 scripts/asent /usr/local/bin/asent
ENV ASENT_DATA=/data PYTHONDONTWRITEBYTECODE=1
ENV ASENT_HOME=/app ASENT_PYTHON=python
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
