FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV LOCKON_DEBUG_PORT=5678
CMD ["bash", "-c", "python debug_server.py --port ${LOCKON_DEBUG_PORT}"]
