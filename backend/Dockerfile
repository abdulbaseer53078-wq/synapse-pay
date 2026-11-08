# API and job workers (same image; the command picks the role). Build from the repo root:
#   docker build -f backend/Dockerfile -t synapsepay-api .
FROM python:3.14.0-slim-bookworm

RUN useradd --uid 10001 --no-create-home app && mkdir /run/app-secrets && chown app /run/app-secrets
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY --chmod=755 docker/write-secrets.sh /usr/local/bin/write-secrets

USER app
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/write-secrets"]
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
