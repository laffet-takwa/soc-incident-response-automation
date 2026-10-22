FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --system --uid 10001 app && mkdir -p /data && chown -R app:app /app /data
USER app
EXPOSE 8080
CMD ["python", "-m", "soc_automation.api"]
