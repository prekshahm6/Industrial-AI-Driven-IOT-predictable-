FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests==2.31.0
COPY simulator.py .
CMD ["python", "simulator.py"]
