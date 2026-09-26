# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ZEROFORM_SIGNING_KEY=""

WORKDIR /app

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY zeroform ./zeroform
COPY gui ./gui
COPY README\ \(1\).markdown ./README.markdown

RUN useradd --create-home --uid 10001 zeroform \
    && mkdir -p /app/.zeroform \
    && chown -R zeroform:zeroform /app
USER zeroform

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health', timeout=3)" || exit 1

CMD ["uvicorn", "zeroform.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
