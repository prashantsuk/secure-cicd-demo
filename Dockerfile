# Minimal, non-root image for the supply chain demo.
# Tip: pin the base image by digest in real use (python:3.12-slim@sha256:...).
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run as an unprivileged user
RUN useradd --system --uid 10001 appuser
USER 10001

EXPOSE 8080
CMD ["python", "app.py"]
