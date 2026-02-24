FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
ARG BUILD_ENV=production
RUN if [ "$BUILD_ENV" = "local" ]; then \
      pip install --no-cache-dir -r requirements.txt 2>/dev/null || \
      pip install --no-cache-dir requests jinja2; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi

COPY . .

ENV PYTHONPATH=/app/src

CMD ["python", "/app/src/main.py"]
