FROM python:3.11-slim

WORKDIR /app

# Copy only deps first so this layer caches unless requirements change
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
#RUN playwright install --with-deps chromium

# Copy the rest of the app
COPY . .

# Run as a non-root user (security best practice for an image)
RUN useradd -m appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
