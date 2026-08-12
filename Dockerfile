FROM python:3-alpine

RUN mkdir -p /app

RUN apk update && \
    apk add uvicorn

RUN pip install --no-cache-dir --upgrade pip

WORKDIR /app

COPY requirements.txt /app
COPY app.py /app

RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 8000
CMD gunicorn app:app -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000


