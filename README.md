# T08 · 소개 페이지에 패스키 달기

T01 `youmjjang/About-me`의 공개 소개·디자인·이미지를 복사하고 비공개 기록 공간만 추가한 별도 프로젝트입니다. 원본 저장소에는 쓰지 않았습니다.

- 원본 기준: https://github.com/youmjjang/About-me/tree/b99a52fe45ca5e373f999cad459d270c6e9b3061
- 새 저장소: https://github.com/youmjjang/About_me_new
- 인증 구현 설명: [T08-AUTH.md](T08-AUTH.md)
- 제출 칸과 실제 기기 확인: [SUBMISSION.md](SUBMISSION.md)
- HTTP 증거: [evidence/http-evidence.json](evidence/http-evidence.json)

## 실행

Node.js 24 이상에서:

```sh
npm ci
npm run build
npx wrangler d1 migrations apply DB --local --config dist/server/wrangler.json
npx wrangler dev --config dist/server/wrangler.json --port 3000 --var ORIGIN:http://localhost:3000
```

`http://localhost:3000`을 사용합니다. `127.0.0.1`은 Origin/RP ID가 달라 인증용 주소로 사용하지 않습니다. 실제 배포 Origin은 `worker/config.mjs`에 고정합니다.

## 검사

`npm test`: Worker 요청 처리 코드와 실제 SimpleWebAuthn 서명 검증을 호출하는 48개 요청 검사. Node SQLite 어댑터와 테스트 전용 ES256 인증기를 사용합니다. 기기의 실제 개인키나 계정은 사용하지 않습니다.

`node test/browser.mjs`: 별도 Playwright와 Edge 설치 후 로컬 Worker/D1에서 브라우저 WebAuthn 가상 인증기 검사. 물리 기기 등록과 구분합니다.

## 구성

- `public/index.html`, `styles.css`, `script.js`, `assets/`: T01 공개 소개. 비공개 내용 없음.
- `public/private/index.html`, `private.js`, `private.css`: 로그인·등록·공개키 목록·삭제 UI.
- `worker/index.mjs`: 모든 인증과 서버의 소유자 검사.
- `db/schema.ts`, `drizzle/`: D1 DB 정의와 마이그레이션.
- `scripts/build.mjs`: Worker ESM과 공개 자산 빌드.

비공개 기록은 가상 자료입니다. 이메일·전화번호·신분증 정보나 비밀번호는 받지 않습니다. 입력한 별칭과 패스키 이름에도 실제 개인정보를 넣지 마세요. 서버의 패스키 삭제와 기기 비밀번호 관리자의 키 삭제는 별개의 작업입니다.
