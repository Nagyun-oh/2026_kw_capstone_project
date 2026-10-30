# Open Source Security Check

## 1. 목적

본 문서는 Spring Boot 백엔드 프로젝트에서 사용하는 오픈소스 의존성을 점검하고,
SBOM을 생성하며, 정적분석 기반의 보안 점검 흐름을 구성한 내용을 정리한다.

오픈소스 라이선스 및 보안취약점 검증, 소스코드 정적분석, 빌드 인프라 운영 흐름을 프로젝트에 적용하는 것을 목표로 한다.

## 2. 적용 대상

- 프로젝트: AI 기반 실시간 보안 위협 탐지 및 분석 시스템
- 대상 모듈: backend
- 주요 기술: Spring Boot, Gradle, Java 17, MySQL, Kafka

## 3. 사용 도구

| 도구 | 목적 |
|---|---|
| OWASP Dependency-Check | 오픈소스 의존성의 알려진 취약점 점검 |
| CycloneDX Gradle Plugin | SBOM 생성 |
| GitHub CodeQL | 소스코드 정적분석 및 취약점 탐지 |
| Gradle | 빌드 및 의존성 관리 |

## 4. 수행 절차

### 4.1 Gradle 의존성 확인

Spring Boot 백엔드 프로젝트에서 사용하는 런타임 의존성 목록을 확인하였다.

```bash
./gradlew dependencies --configuration runtimeClasspath
```

Windows PowerShell 환경에서는 다음 명령어를 사용하였다.

```powershell
.\gradlew dependencies --configuration runtimeClasspath
```

이를 통해 프로젝트가 직접 사용하는 라이브러리뿐 아니라, 전이 의존성까지 함께 확인할 수 있다.

---

### 4.2 CycloneDX SBOM 생성

프로젝트의 오픈소스 구성요소를 식별하기 위해 CycloneDX Gradle Plugin을 사용하여 SBOM을 생성하였다.

```bash
./gradlew cyclonedxDirectBom
```

Windows PowerShell 환경에서는 다음 명령어를 사용하였다.

```powershell
.\gradlew cyclonedxDirectBom
```

생성 결과는 다음 경로에 저장된다.

```text
build/reports/cyclonedx-direct/bom.json
build/reports/cyclonedx-direct/bom.xml
```

SBOM에는 프로젝트에서 사용하는 라이브러리명, 버전, 패키지 정보 등이 포함되며, 이를 통해 소프트웨어 구성요소를 문서화할 수 있다.

---

### 4.3 OWASP Dependency-Check 실행

오픈소스 의존성에 알려진 보안 취약점이 존재하는지 확인하기 위해 OWASP Dependency-Check를 실행하였다.

```bash
./gradlew dependencyCheckAnalyze
```

Windows PowerShell 환경에서는 다음 명령어를 사용하였다.

```powershell
.\gradlew dependencyCheckAnalyze
```

생성 결과는 다음 경로에 저장된다.

```text
build/reports/dependency-check/dependency-check-report.html
build/reports/dependency-check/dependency-check-report.json
```

HTML 리포트를 통해 취약점이 발견된 라이브러리, CVE 번호, CVSS 점수, 취약점 설명 등을 확인할 수 있다.

---

### 4.4 NVD API Key 설정

Dependency-Check는 NVD 취약점 데이터베이스를 기반으로 의존성 취약점을 분석한다.  
API Key 없이 실행할 경우 요청 제한으로 인해 분석이 실패할 수 있으므로, NVD API Key를 환경변수로 설정하였다.

PowerShell에서 다음과 같이 설정하였다.

```powershell
$env:NVD_API_KEY="발급받은_API_KEY"
```

Gradle 설정에서는 환경변수 값을 읽도록 구성하였다.

```gradle
nvd {
    apiKey = System.getenv("NVD_API_KEY")
}
```

이를 통해 API Key를 소스코드에 직접 노출하지 않고, 실행 환경에서 안전하게 참조할 수 있도록 하였다.

---

### 4.5 GitHub CodeQL 정적분석 구성

소스코드 정적분석을 자동화하기 위해 GitHub Actions 기반 CodeQL Workflow를 추가하였다.

Workflow 파일은 다음 경로에 생성하였다.

```text
.github/workflows/codeql.yml
```

CodeQL은 push 또는 pull request 발생 시 Java/Kotlin 코드를 분석하도록 구성하였다.  
이를 통해 코드 내 잠재적인 보안 취약점이나 오류를 CI 단계에서 자동으로 탐지할 수 있다.

---

### 4.6 점검 결과 확인

SBOM 생성 결과와 Dependency-Check 분석 결과를 확인하였다.

```powershell
Get-ChildItem .\build\reports\cyclonedx-direct
Get-ChildItem .\build\reports\dependency-check
```

확인 대상 파일은 다음과 같다.

```text
bom.json
bom.xml
dependency-check-report.html
dependency-check-report.json
```

최종적으로 Spring Boot 백엔드 모듈에 대해 오픈소스 구성요소 식별, SBOM 생성, 의존성 취약점 점검, 정적분석 자동화 흐름을 구성하였다.
