FROM python:3.12-alpine

ARG APP_DIR="/layer"

WORKDIR ${APP_DIR}

COPY requirements.txt connector.py ${APP_DIR}/

RUN python -m pip install --upgrade pip \
    && pip install --target ${APP_DIR} -r requirements.txt
