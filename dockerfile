# log2http service
#
# VERSION               0.0.1
FROM python:3
MAINTAINER LuRui <lr@9fwealth.com>

ADD app /app

RUN apt-get update && apt-get install -yy aria2 && apt-get clean
RUN pip install -r /app/requirements.txt

WORKDIR /app
ENTRYPOINT ["python", "main.py"]