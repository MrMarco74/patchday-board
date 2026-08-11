FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5099

ENV LISTEN_PORT=5099
ENV OLLAMA_URL=http://localhost:11434

CMD ["python", "patchday_backend.py"]
