FROM mcr.microsoft.com/playwright/python:v1.49.1-noble
RUN pip install --no-cache-dir playwright==1.49.1
COPY watch.py /app/watch.py
ENV PYTHONUNBUFFERED=1 REPO_DIR=/repo STATE_DIR=/state
ENTRYPOINT ["python3", "/app/watch.py"]
