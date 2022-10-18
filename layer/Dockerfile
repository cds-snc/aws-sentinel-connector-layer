FROM python:3.9.7-alpine3.14@sha256:a31add3a2442bceecb9d4f66e575072c4d4a1c7e561b7fe44cdf0dd277685276

ARG APP_DIR="/layer"

WORKDIR ${APP_DIR}

COPY requirements.txt connector.py ${APP_DIR}/

RUN python -m pip install --upgrade pip \
    && pip install --target ${APP_DIR} -r requirements.txt
