FROM python:3.9-slim-buster

WORKDIR /backend

RUN apt-get update \
	&& apt-get install -y whois \
	&& apt-get clean  \
	&& rm -rf /var/lib/apt/lists/*

COPY pyproject.toml poetry.lock README.md /backend/
COPY abuse_whois /backend/abuse_whois
COPY gunicorn.conf.py /backend/

RUN pip install -U pip && \
	pip install poetry \
	&& poetry install --extras api --no-dev

ENV PORT 8000

EXPOSE $PORT

CMD poetry run gunicorn -k uvicorn.workers.UvicornWorker abuse_whois.api.app:app
