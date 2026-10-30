# React 빌드 단계
FROM node:22-alpine AS build

WORKDIR /app

# 의존성 정보부터 복사
COPY package.json package-lock.json ./

# 잠금 파일에 기록된 버전으로 설치
RUN npm ci

# React 빌드에 필요한 파일 복사
COPY public/ public/
COPY src/ src/

# HTML, CSS, JavaScript 생성
RUN npm run build

# 화면 제공 단계
FROM nginx:stable-alpine AS runtime

# Nginx 기본 서버 설정 교체
COPY nginx.conf /etc/nginx/conf.d/default.conf

# React 빌드 결과만 복사
COPY --from=build /app/build/ /usr/share/nginx/html/

EXPOSE 80

CMD ["nginx","-g","daemon off;"]