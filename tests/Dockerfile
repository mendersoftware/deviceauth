FROM python:3

RUN pip3 install --quiet bravado==9.2.2 pymongo==3.6.1 pytest-ordering==0.5 minio pycrypto pytest==3.10.1 twisted requests pyyaml flask tornado

RUN mkdir -p /testing
ENTRYPOINT ["bash", "/testing/run.sh"]
