FROM python:3.11-slim
WORKDIR /workspace
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
ENV LOCKON_DEBUG_PORT=5678
CMD ["sleep", "infinity"]
