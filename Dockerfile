# Dockerfile for AWS Nitro Enclave image
FROM amazonlinux:2

# Install python3 and pip explicitly
RUN yum install -y python3 python3-pip && \
    yum clean all

# Install crypto dependencies
RUN pip3 install pycryptodome

# Copy enclave application
WORKDIR /app
COPY enclave_app.py .

CMD ["/usr/bin/python3", "-u", "/app/enclave_app.py"]