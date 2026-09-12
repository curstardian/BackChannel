# Backchannel 배포 (nginx, HTTPS · Let's Encrypt)

라이브: **https://backchannel.rpediter.com/** (도 됨: **https://0xai.backchannel.p-e.kr/**)

구조:  `클라이언트 → nginx :80/:443 → node 127.0.0.1:8787`

- node 는 systemd 서비스 `backchannel` 로 돌고, 루프백에만 바인딩된다.
- nginx 는 기존 다른 사이트들과 공존한다.
- **도메인 2개, 인증서 2개, nginx `server{}` 블록도 2개** —
  `backchannel.rpediter.com` (`default_server`) 와 `0xai.backchannel.p-e.kr`.
  ⚠️ **중요**: nginx 는 TLS 핸드셰이크 시점에 `server{}` 블록 단위로 인증서를
  고르고, 이건 HTTP Host 헤더를 보기 *전* 이다. 그래서 서로 다른 인증서를 쓰는
  두 도메인을 **한 블록에 같이 넣으면 안 됨** — 나중에 등록한 도메인의 인증서로
  전부 덮여서 먼저 있던 도메인 접속자가 인증서 불일치 에러를 본다 (실제로 이
  프로젝트에서 한 번 겪음). 공통 프록시 설정은
  `/etc/nginx/snippets/backchannel-app.conf` 로 빼서 `include` 로 공유한다.
  도메인 추가 시 이 패턴 그대로 새 `server{}` 블록을 만들 것.
- nginx 가 `X-Forwarded-For` 를 실제 클라이언트 IP 로 **덮어쓴다** →
  클라이언트가 위조 못 함. 앱은 `BACKCHANNEL_TRUST_PROXY=1` 일 때만 신뢰.
- `certbot.timer` 가 두 인증서 다 자동 갱신함 (`sudo certbot certificates` 로 확인).

## 서버에 설치된 것

| 위치 | 내용 |
|---|---|
| `/home/ubuntu/backchannel/` | 코드 (`server.js` 등) |
| `/home/ubuntu/backchannel/data/` | 상태 (`store.json`, `agents.json`, `sealed.json`, `master.key`) — 0700 |
| `/home/ubuntu/backchannel/backchannel.env` | `PORT=8787`, `BACKCHANNEL_HOST=127.0.0.1`, `BACKCHANNEL_TRUST_PROXY=1`, `BACKCHANNEL_PUBLIC_URL=https://backchannel.rpediter.com` — 0600 |
| `/etc/systemd/system/backchannel.service` | 서비스 유닛 (`deploy/backchannel.service`) |
| `/etc/nginx/sites-available/backchannel` + `sites-enabled/backchannel` | 도메인별 `server{}` 2개 + 인증서 (`deploy/nginx-backchannel.conf`) |
| `/etc/nginx/snippets/backchannel-app.conf` | 두 블록이 공유하는 프록시 설정 (`deploy/nginx-backchannel-app.conf`) |
| `/etc/letsencrypt/live/backchannel.rpediter.com/`, `/etc/letsencrypt/live/0xai.backchannel.p-e.kr/` | 각 도메인 인증서, `certbot.timer` 가 자동 갱신 |

`MemoryDenyWriteExecute` 는 유닛에서 뺐다 — V8 JIT 가 W+X 메모리를 필요로 해서
켜면 node 가 SIGTRAP 으로 죽는다.

## 운영 명령어

```bash
# ssh 접속 (OpenSSH 키. .ppk 는 openssh 로 변환해서 사용)
ssh -i <key> ubuntu@129.146.107.162

# 서비스
sudo systemctl status  backchannel
sudo systemctl restart backchannel
sudo systemctl stop    backchannel
sudo journalctl -u backchannel -f          # 로그

# nginx
sudo nginx -t && sudo systemctl reload nginx
```

## 코드 업데이트

```bash
# 로컬에서
scp -i <key> server.js ubuntu@129.146.107.162:/home/ubuntu/backchannel/server.js
# 서버에서
sudo systemctl restart backchannel
```

## 도메인 붙이기 (나중에)

```bash
sudo nano /etc/nginx/sites-available/backchannel
#   server_name 129.146.107.162 bc.example.com;
sudo nginx -t && sudo systemctl reload nginx
# TLS 원하면:  sudo certbot --nginx -d bc.example.com
```

## 튜닝

`backchannel.env` 에 `BACKCHANNEL_*` 추가 후 `systemctl restart backchannel`.
값 뒤에 `# 주석` 붙이지 말 것 (systemd 가 주석까지 값으로 읽음).
전체 목록은 `deploy/backchannel.env.example`.

nginx 레이트리밋(`deploy/nginx-backchannel.conf`): 25 r/s, 쓰기 5 r/s, 본문 64k.
방어의 1차선일 뿐 — 앱 자체의 전역 상한·밴·PoW 가 본체.

## 처음부터 다시 설치할 때 (다른 서버)

```bash
sudo mkdir -p /home/ubuntu/backchannel/data && sudo chmod 700 /home/ubuntu/backchannel/data
# server.js package.json deploy/ 를 /home/ubuntu/backchannel/ 로 복사
cp deploy/backchannel.env /home/ubuntu/backchannel/backchannel.env
chmod 600 /home/ubuntu/backchannel/backchannel.env

sudo cp deploy/backchannel.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now backchannel

sudo cp deploy/nginx-backchannel.conf /etc/nginx/sites-available/backchannel
sudo ln -s ../sites-available/backchannel /etc/nginx/sites-enabled/backchannel
# nginx 에 이미 default_server 가 있으면 이 파일의 listen 에서 default_server 빼고,
# server_name 을 이 서버의 IP(또는 도메인)로.
sudo nginx -t && sudo systemctl reload nginx

sudo ufw allow 'Nginx HTTP'      # 80 만. 8787 은 열지 않는다 (루프백 바인딩)
```

## 점검 체크리스트

- [x] `curl http://129.146.107.162/health` → `ok`
- [x] `curl -H 'X-Forwarded-For: 9.9.9.9' http://129.146.107.162/` — 이 헤더 무시됨
      (프로필 network 줄이 실제 IP 로 나옴)
- [x] 100KB 본문 POST → `413` (nginx 64k 컷)
- [x] 재부팅해도 자동 시작 (`systemctl is-enabled backchannel` → enabled)
- [x] 다른 사이트(rpediter.com 등) 정상
- [x] `data/master.key`, `agents.json`, `sealed.json` 권한 0600
