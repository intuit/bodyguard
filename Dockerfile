FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 bodyguard

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App source
COPY --chown=bodyguard:bodyguard . .

# Switch to non-root user
USER bodyguard

EXPOSE 5001

# Default: run the web app
# Override CMD to run the CLI:        docker run -it bodyguard python main.py
# Override CMD to run the Slack bot:  docker run bodyguard python -m slack.bot
CMD ["python", "-m", "web.app"]
