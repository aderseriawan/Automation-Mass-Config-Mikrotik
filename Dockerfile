# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Jakarta

WORKDIR /app

# deps build (cryptography, Pillow, dll)
RUN apt-get update && \
    apt-get install -y build-essential libffi-dev libjpeg-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

COPY NA_Project/requirements.txt .
RUN --mount=type=cache,target=/root/.cache \
    pip install --upgrade pip && pip install -r requirements.txt

# copy source
COPY NA_Project/ .

# direktori statik & media
RUN mkdir -p static media

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["gunicorn", "NA_Project.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
