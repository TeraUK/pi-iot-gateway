FROM python:3.11-slim

# Install ML and data processing dependencies.
RUN pip install --no-cache-dir \
    pandas \
    scikit-learn \
    numpy \
    requests \
    pyyaml \
    joblib

RUN mkdir -p /opt/ml-pipeline
WORKDIR /opt/ml-pipeline

COPY app/ /opt/ml-pipeline/

# The pipeline script. Override via docker-compose command if needed.
CMD ["python", "-u", "pipeline.py"]
