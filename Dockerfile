# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Jakarta

WORKDIR /app

# ----- sistem build deps (optional, tapi berguna utk cryptography dkk) -----
RUN apt-get update && apt-get install -y build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ----- Python deps -----
COPY NA_Project/requirements.txt ./requirements.txt
RUN --mount=type=cache,target=/root/.cache \
    pip install --upgrade pip && \
    pip install -r requirements.txt

# ----- Copy source -----
COPY NA_Project/ .

# pastikan folder statik / media / db ada
RUN mkdir -p static media db

EXPOSE 8000
CMD ["gunicorn", "NA_Project.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
