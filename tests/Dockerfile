FROM python:3.8

RUN pip3 install --quiet bravado==9.2.2 pymongo==3.11.0 pytest-ordering==0.6 minio cryptography==3.1.1 pytest==6.1.1 twisted requests pyyaml flask tornado

RUN mkdir -p /testing
ENTRYPOINT ["bash", "/testing/run.sh"]
