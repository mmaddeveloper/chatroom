# Chatroom Pack v6.2 — More Bugfixes (Private Invite + Broadcast Throttle)

## Fixed
- Private channels no longer block invite/request joins before policy handling.
  - If a channel is `visibility=private` and user is not a member:
    - `joinPolicy=invite` works with token
    - `joinPolicy=request` lets user submit request
    - other policies still deny (as expected)
- Throttled channel list broadcast after settings changes (250ms) + safer async loop
- Cleanup rate-limit bucket for socket on disconnect
- Also emits legacy `update_channels` for older clients

## Run
```bash
npm i
npm start
```


## Added in v6.4
- `emitChannelsTo` now emits both `update_channels` (legacy) and `update_channels_v2`
- Added `/health` endpoint
- Minor cleanup (no variable shadowing)


---

## نصب و اجرا با یک دستور (Ubuntu/Debian)

> این دستور کل پروژه رو از GitHub دانلود می‌کنه، unzip می‌کنه، dependencyها رو نصب می‌کنه و اجرا می‌کنه.
> **جایگزین کن:** `YOUR_GITHUB_USER` و `YOUR_REPO`

```bash
bash -c 'set -e; REPO="https://github.com/YOUR_GITHUB_USER/YOUR_REPO"; BRANCH="main"; curl -fsSL "$REPO/archive/refs/heads/$BRANCH.zip" -o repo.zip; unzip -q repo.zip; cd "$(ls -d *-*/ | head -n1)"; npm i; npm start'
```

### اگر curl نداری
```bash
sudo apt-get update && sudo apt-get install -y curl unzip
```

---

## اجرا (بعد از کلون کردن یا دانلود)

```bash
npm i
npm start
```

سپس مرورگر:
- `http://localhost:3000`

---

## نکتهٔ Deploy پشت Nginx (اختیاری)

اگر پشت reverse proxy هستی و IP واقعی مهمه، حتماً header `X-Forwarded-For` رو پاس بده و `trust proxy` فعاله (تو این پروژه فعاله).
