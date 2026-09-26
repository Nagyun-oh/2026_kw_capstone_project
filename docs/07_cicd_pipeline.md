# CI/CD 파이프라인

GitHub Actions로 테스트·빌드를 자동화하고, `develop` 반영 시 단일 EC2([06_aws_deployment.md](06_aws_deployment.md))에 자동 배포하는 구성을 정리한다.

## 1. 구성 요약

| 구분 | 상태 | 파일 |
| --- | --- | --- |
| CI (테스트·빌드·AI 기동 확인) | 적용 | [.github/workflows/ci.yml](../.github/workflows/ci.yml) |
| 모델 버전 고정·검증 | 적용 | [AI_new/models.lock.json](../AI_new/models.lock.json), [scripts/fetch_models.py](../scripts/fetch_models.py) |
| AWS·GitHub 사전 설정 | 진행 필요 (4~5장) | - |
| CD (ECR push → EC2 배포) | 예정 | `.github/workflows/deploy.yml` |

**변경 전:** EC2에 SSH 접속 → `git pull` → 모델 수동 전달 → EC2에서 이미지 빌드.

**변경 후 (CD 적용 시):**

```
develop에 merge
   │
   ▼
GitHub Actions
 ├─ CI : 백엔드 테스트(MySQL) · 프론트 빌드 · AI 이미지 빌드 + /health · Compose 검증
 └─ CD : 모델 다운로드·SHA-256 검증 → 이미지 3개 빌드 → ECR push (태그 = git SHA)
   │     AWS 인증은 OIDC 임시 자격 증명 (GitHub에 AWS 키 저장 안 함)
   ▼
SSM Run Command → EC2
   git checkout <SHA> → ECR 이미지 pull → docker compose up -d → health 확인
```

설계 원칙:

- **이미지는 CI에서 빌드한다.** EC2에서 torch 설치·빌드를 하지 않아 메모리·시간 부담이 없다.
- **이미지 태그 = git SHA.** 어떤 코드와 모델이 배포됐는지 태그로 추적하고, 이전 SHA로 되돌려 롤백한다.
- **비밀값은 EC2의 `.env.aws`에만 둔다.** GitHub를 거치지 않는다.
- **SSH 포트를 배포에 사용하지 않는다.** SSM으로 명령을 전달한다.

## 2. CI (`ci.yml`)

`develop`·`main`에 대한 push·PR에서 실행된다.

| Job | 내용 |
| --- | --- |
| Backend test & build | MySQL 8.0 서비스 컨테이너에 `docs/db/security-db-schema.sql` 적용 후 `./gradlew test bootJar`. 실패 시 테스트 리포트를 artifact로 업로드 |
| Frontend build | `npm ci` → `npm run build` |
| AI image build & health | 모델 다운로드·검증 → `AI_new` 이미지 빌드 → 컨테이너 기동 후 `/health`의 `model_loaded=true` 확인 |
| Compose configuration | 로컬·AWS·WAF Compose 파일 문법 검증 (더미 환경변수 사용) |

- 백엔드 `contextLoads`는 실제 DB 연결과 JPA `validate`를 수행하므로 MySQL이 필요하다. Kafka는 필요 없다.
- AI job은 Kafka 없이 모델 로딩까지만 확인한다. Kafka 연동은 배포 환경에서 확인한다.
- 모델 파일은 `models.lock.json` 해시를 키로 캐시하며, 캐시를 사용해도 SHA-256을 다시 검증한다.

## 3. 모델 버전 관리

AI 팀은 Kaggle 데이터셋 `hyunwook23/capstone-new2026`에 모델을 올린다. 서버에 배포할 버전은 Git의 `AI_new/models.lock.json`이 결정한다.

```bash
python3 scripts/fetch_models.py   # 저장소 루트에서 실행
```

- 데이터셋 전체(약 1.3GB)가 아니라 lock에 적힌 파일만 지정 버전으로 받는다.
- SHA-256이 다르면 파일을 저장하지 않고 실패한다. `.pkl`은 로드 시 임의 코드를 실행할 수 있기 때문이다.
- 모델 교체: Kaggle 새 버전 업로드 → `version`과 `sha256` 갱신 PR → CI 통과 확인 후 merge. 트랜스포머를 바꾸면 `model_bundle.pkl.manifest.json`도 함께 갱신한다.

## 4. AWS 사전 설정

리전은 서울(`ap-northeast-2`)이다. 아래 `<ACCOUNT_ID>`는 12자리 AWS 계정 ID, `<INSTANCE_ID>`는 EC2 인스턴스 ID(`i-...`)로 바꾼다. 둘 다 콘솔 우측 상단 계정 메뉴와 EC2 인스턴스 목록에서 확인한다.

### 4-1. ECR 저장소 3개

ECR → Private repositories → Create repository. 다음 설정으로 3개를 만든다.

| 항목 | 값 |
| --- | --- |
| 이름 | `security-backend`, `security-frontend`, `security-ai` |
| Tag immutability | Immutable (SHA 태그를 덮어쓰지 않음) |
| 암호화 | 기본값(AES-256) |

각 저장소 → Lifecycle policy → Create rule(또는 JSON 편집)으로 최근 10개 이미지만 남긴다.

```json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "keep last 10 images",
      "selection": { "tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 10 },
      "action": { "type": "expire" }
    }
  ]
}
```

### 4-2. GitHub OIDC 공급자

IAM → Identity providers → Add provider.

| 항목 | 값 |
| --- | --- |
| Provider type | OpenID Connect |
| Provider URL | `https://token.actions.githubusercontent.com` |
| Audience | `sts.amazonaws.com` |

### 4-3. GitHub Actions용 IAM Role (`github-actions-deploy`)

IAM → Roles → Create role → **Custom trust policy**에 아래를 넣는다. 이 저장소의 `develop` 브랜치에서 실행된 workflow만 이 Role을 사용할 수 있다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:Nagyun-oh/2026_kw_capstone_project:ref:refs/heads/develop"
        }
      }
    }
  ]
}
```

권한은 관리형 정책을 붙이지 않고, Role 생성 후 **Add permissions → Create inline policy → JSON**으로 아래만 부여한다. (ECR push, 해당 EC2에 대한 셸 명령 전달, 결과 조회)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EcrLogin",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "EcrPush",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage"
      ],
      "Resource": [
        "arn:aws:ecr:ap-northeast-2:<ACCOUNT_ID>:repository/security-backend",
        "arn:aws:ecr:ap-northeast-2:<ACCOUNT_ID>:repository/security-frontend",
        "arn:aws:ecr:ap-northeast-2:<ACCOUNT_ID>:repository/security-ai"
      ]
    },
    {
      "Sid": "DeployToInstance",
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": [
        "arn:aws:ec2:ap-northeast-2:<ACCOUNT_ID>:instance/<INSTANCE_ID>",
        "arn:aws:ssm:ap-northeast-2::document/AWS-RunShellScript"
      ]
    },
    {
      "Sid": "ReadCommandResult",
      "Effect": "Allow",
      "Action": ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"],
      "Resource": "*"
    }
  ]
}
```

생성 후 Role의 **ARN**(`arn:aws:iam::<ACCOUNT_ID>:role/github-actions-deploy`)을 복사해 둔다.

### 4-4. EC2 Instance Role (`ec2-security-platform`)

1. IAM → Roles → Create role → Trusted entity: **AWS service / EC2**.
2. 관리형 정책 2개를 붙인다.
   - `AmazonSSMManagedInstanceCore` (SSM 명령 수신)
   - `AmazonEC2ContainerRegistryReadOnly` (ECR 이미지 pull)
3. EC2 → 인스턴스 선택 → Actions → Security → **Modify IAM role** → 위 Role 선택.

### 4-5. EC2에서 확인 (ubuntu 계정)

```bash
# SSM Agent는 Ubuntu 공식 AMI에 snap으로 기본 설치돼 있다. Role 연결 후 재시작해 인식시킨다.
sudo snap services amazon-ssm-agent
sudo snap restart amazon-ssm-agent

# AWS CLI 설치
sudo snap install aws-cli --classic

# Instance Role로 인증되는지 확인 → Arn에 assumed-role/ec2-security-platform 이 보여야 한다
aws sts get-caller-identity

# ECR 로그인 확인 → Login Succeeded
aws ecr get-login-password --region ap-northeast-2 \
  | sudo docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com
```

콘솔 Systems Manager → **Fleet Manager**에서 인스턴스가 `Online`으로 표시되면 SSM 준비가 끝난 것이다.

> SSM Run Command는 root로 실행된다. 저장소는 ubuntu 소유이므로 배포 스크립트는 git 명령을 `sudo -u ubuntu`로 실행한다. root로 git을 실행하면 `dubious ownership` 오류와 root 소유 파일이 생긴다.

## 5. GitHub 설정

저장소 → Settings → Secrets and variables → Actions → **Variables** 탭에 등록한다. 비밀값이 아니므로 Secrets가 아닌 Variables를 사용한다.

| 이름 | 값 |
| --- | --- |
| `AWS_REGION` | `ap-northeast-2` |
| `AWS_ROLE_ARN` | 4-3의 Role ARN |
| `ECR_REGISTRY` | `<ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com` |
| `EC2_INSTANCE_ID` | `<INSTANCE_ID>` |

## 6. 설정 완료 체크리스트

- [ ] ECR 저장소 3개 생성, Immutable·Lifecycle policy 적용
- [ ] IAM OIDC 공급자 등록
- [ ] `github-actions-deploy` Role: trust policy(develop 제한) + inline policy
- [ ] `ec2-security-platform` Role 생성 및 인스턴스 연결
- [ ] EC2: `aws sts get-caller-identity`, ECR `Login Succeeded`, Fleet Manager `Online`
- [ ] GitHub Variables 4개 등록

## 7. 보안·비용 메모

- GitHub에는 장기 AWS 키가 없다. OIDC 토큰은 workflow 실행 동안만 유효하다.
- `github-actions-deploy`는 이 저장소의 `develop`에서만, 3개 ECR 저장소와 1개 인스턴스에만 권한이 있다.
- ECR 비용은 저장 용량 기준이며 Lifecycle policy로 이미지 10개만 유지한다. AI 이미지는 CPU 전용 torch라 수백 MB~1GB 수준이다.
- ECR 기본 스캔(OS 패키지 취약점)은 추가 비용이 없다. ECR → Private registry → Scanning configuration에서 push 시 스캔을 켤 수 있다.
