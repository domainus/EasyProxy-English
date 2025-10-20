# Stage 1: Build
# Use an official lightweight Python image as the base.
FROM python:3.11-slim

# Set the working directory inside the container.
WORKDIR /app

# Copy the dependency file.
# Doing this before the rest of the code takes advantage of Docker's cache if dependencies don't change.
COPY requirements.txt .

# Install dependencies.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the working directory.
COPY . .

# Correct OCI (Open Container Initiative) image metadata.
LABEL org.opencontainers.image.title="HLS Proxy Server"
LABEL org.opencontainers.image.description="Universal proxy server for HLS streams with support for Vavoo, DLHD, and playlist builder"
LABEL org.opencontainers.image.version="2.5.0"
LABEL org.opencontainers.image.source="https://github.com/domainus/EasyProxy-English"

# Expose the port the application listens on.
EXPOSE 7860

# Command to start the app in production with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "--workers", "4", "--worker-class", "aiohttp.worker.GunicornWebWorker", "app:app"]