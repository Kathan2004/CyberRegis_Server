FROM python:3.11-slim

# Install matplotlib dependencies
RUN apt-get update && \
    apt-get install -y libfreetype6-dev libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD gunicorn -w 4 -b 0.0.0.0:${PORT:-4000} KALE:app