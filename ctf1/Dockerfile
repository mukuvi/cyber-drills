FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    dnsutils \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

COPY app /app

RUN pip install --no-cache-dir -r /app/requirements.txt


ENV FLASK_APP=/app/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
ENV FLASK_DEBUG=0


COPY init.sh /init.sh
RUN chmod +x /init.sh
CMD ["/init.sh"]
