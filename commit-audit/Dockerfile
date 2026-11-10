FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "mistralai-workflows>=3.10" \
    "mistralai-workflows[mistralai]" \
    "mistralai>=3.0" \
    "httpx>=0.27" \
    "pydantic>=2"

COPY src ./src
ENV PYTHONPATH=/app/src

CMD ["python", "-m", "worker.entrypoints.worker"]
