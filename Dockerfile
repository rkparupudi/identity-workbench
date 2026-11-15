FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IDW_HOME=/data/store \
    IDW_DATA_DIR=/data/files

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY workbench ./workbench
COPY web ./web
COPY tests ./tests
RUN pip install --no-cache-dir ".[all]" && mkdir -p /data/store /data/files

WORKDIR /data/files
EXPOSE 8501 8000
# Default: the web app. docker-compose.yml also starts the API.
CMD ["streamlit", "run", "/app/web/app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true", "--browser.gatherUsageStats=false"]
