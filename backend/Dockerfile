FROM python:3.11-slim

WORKDIR /app

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Copy only deps first so this layer caches unless requirements change
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# playwright's bundled node driver needs libatomic, which the slim image doesn't ship
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 && rm -rf /var/lib/apt/lists/*
RUN playwright install --with-deps chromium

# Copy the rest of the app
COPY . .

# Run as a non-root user (security best practice for an image)
RUN useradd -m appuser && chown -R appuser /ms-playwright
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
