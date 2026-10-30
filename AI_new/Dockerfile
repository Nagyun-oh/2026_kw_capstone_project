FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./

# CPU 전용 torch 휠을 사용해 CUDA 의존성(수 GB)을 설치하지 않는다.
# 트랜스포머 번들은 torch major.minor(2.8)만 검증하므로 +cpu 빌드와 호환된다.
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home \
        --shell /usr/sbin/nologin app

COPY --chown=app:app main.py features_v2.py schema_expert.py ./
COPY --chown=app:app security_ai ./security_ai
COPY --chown=app:app models ./models

USER app

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
