FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

# Single worker keeps the in-process seeding simple and deterministic.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]
