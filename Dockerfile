# syntax=docker/dockerfile:1
# One image, many services: the command decides which microservice runs
# (`aegis run collector`, `aegis run auth-analyzer`, `aegis api`, ...).

# ---------- build stage: install dependencies and train the ML models ----------
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
# Copy only the dependency manifest first so this layer is cached between code changes.
COPY pyproject.toml README.md ./
RUN mkdir -p src/aegis && touch src/aegis/__init__.py && pip install ".[infra]" && pip uninstall -y aegis
COPY src ./src
COPY config ./config
COPY knowledge ./knowledge
RUN pip install --no-deps .
# Bake trained models into the image: deterministic (fixed seed) and avoids training at startup.
RUN AEGIS_MODEL_DIR=/app/models AEGIS_REPORT_DIR=/app/ml/reports aegis train --seed 7 > /dev/null

# ---------- runtime stage: small, non-root ----------
FROM python:3.12-slim AS runtime
# (No apt packages needed: the scikit-learn / xgboost wheels bundle their native libraries.)
RUN useradd --uid 10001 --create-home aegis
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    AEGIS_MODEL_DIR=/app/models \
    AEGIS_REPORT_DIR=/app/ml/reports \
    AEGIS_RULES_DIR=/app/config/rules \
    AEGIS_KNOWLEDGE_DIR=/app/knowledge \
    AEGIS_ARCHIVE_DIR=/tmp/archive
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --from=build /app/models /app/models
COPY --from=build /app/ml /app/ml
COPY config ./config
COPY knowledge ./knowledge
USER 10001
EXPOSE 8000 9100
CMD ["aegis", "api"]
