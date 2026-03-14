FROM python:3.11-slim
WORKDIR /app

COPY api/requirements.txt ./requirements.txt
RUN pip install --upgrade pip --no-cache-dir && \
    pip install --no-cache-dir -r requirements.txt

COPY ml_engine/    /app/ml_engine/
COPY trust_engine/ /app/trust_engine/
COPY fleet_graph/  /app/fleet_graph/
COPY api/main.py   /app/main.py

RUN touch /app/ml_engine/__init__.py \
          /app/trust_engine/__init__.py \
          /app/fleet_graph/__init__.py

ENV PYTHONPATH=/app
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
