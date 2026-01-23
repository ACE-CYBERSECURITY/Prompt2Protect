FROM python:3.12-slim

RUN pip install --no-cache-dir requests

WORKDIR /app
COPY server.py /app/server.py
COPY challenges.json /app/challenges.json

CMD ["python", "/app/server.py"]

