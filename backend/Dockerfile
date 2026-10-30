# Java 17로 백엔드를 빌드하는 단계
FROM eclipse-temurin:17-jdk-jammy AS build

# 이미지 내부의 작업 디렉토리
WORKDIR /workspace

# 빌드에 필요한 Gradle 파일 복사
COPY gradlew build.gradle settings.gradle ./
COPY gradle/ gradle/

# 애플리케이션 소스 코드 복사
COPY src/main src/main

# Windows 줄바꿈을 Linux 형식을 정리한 뒤 JAR 빌드
RUN sed -i 's/\r$//' gradlew && sh ./gradlew --no-daemon bootJar

# Java 실행 환경만 포함한 별도 단계
FROM eclipse-temurin:17-jre-jammy AS runtime

WORKDIR /app

# 실행 사용자 생성
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app \
        --no-create-home --shell /usr/sbin/nologin app

# 빌드한 JAR 가져오기
COPY --from=build --chown=app:app \
    /workspace/build/libs/*.jar /app/app.jar

# 서버 실행 방법 지정
USER app

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
