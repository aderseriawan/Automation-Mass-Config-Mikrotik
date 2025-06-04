FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY NA_Project/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY NA_Project/ .

# Create directories for static and media files
RUN mkdir -p static media

# Expose port
EXPOSE 8000

# Start command
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
