# Use a lightweight Python base image
FROM python:3.11-slim

# Install TShark and matplotlib dependencies
RUN apt-get update && \
    apt-get install -y tshark libfreetype6-dev libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements.txt
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port Railway assigns
EXPOSE $PORT

# Run the Flask app with gunicorn
CMD gunicorn -w 4 -b 0.0.0.0:$PORT KALE:app