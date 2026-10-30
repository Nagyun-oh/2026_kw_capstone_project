# 시스템 아키텍처

## 전체 구조
![alt text](images/02_image.png)

## 구성 요소

### Backend Server
- 로그 수집 API 제공
- 로그 조회 API 제공
- AI 분석 모듈과 연동
- 대시보드에 필요한 데이터 제공

### Database
- 로그 데이터 저장
- 보안 이벤트 결과 저장
- 조회 및 통계 기능 지원

### AI Analysis Module
- 저장된 로그 또는 실시간 로그를 분석
- 이상 징후 탐지
- 위험도 판단

### Dashboard
- 로그 목록 조회
- 보안 이벤트 시각화
- 통계 및 알림 정보 제공

### Cloud/Infra
- 백엔드 서버 배포
- DB 실행 환경 구성
- Docker 기반 실행 환경 구성