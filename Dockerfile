FROM python:3.11-slim

# git: needed by Module 1's --github-org repo cloning
# build-essential: needed to build tree-sitter's native extension
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persisted across restarts: run history (sqlite) + scan config
VOLUME ["/app/backend/data"]

EXPOSE 8000

WORKDIR /app/backend
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
