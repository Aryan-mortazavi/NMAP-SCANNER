"""Integration test for the login flow (captcha + access code).

Runs the FastAPI app in-process via ASGI so the test can read the captcha
answer from the server's own memory (white-box) — no bypass exists in the
real running server.
"""

import asyncio
import os

import httpx

import app as appmod

# Never hardcode credentials here — read from .env (via config/dotenv)
PASSWORD = os.getenv("ACCESS_CODE", "")


async def main() -> None:
    if not PASSWORD:
        raise SystemExit("ACCESS_CODE is not set in .env — cannot run tests.")
    transport = httpx.ASGITransport(app=appmod.app)
    ok = True

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        async def fresh_captcha() -> tuple[str, str]:
            d = (await c.get("/api/captcha")).json()
            answer = appmod._captcha_challenges[d["id"]][0]  # peek (white-box)
            return d["id"], answer

        # 1. wrong captcha is rejected
        cid, _ = await fresh_captcha()
        r = await c.post("/api/login", json={
            "code": PASSWORD, "captcha_id": cid, "captcha": "XXXXX",
        })
        passed = r.status_code == 400
        ok &= passed
        print(f"1. wrong captcha   -> {r.status_code} {'PASS' if passed else 'FAIL'} {r.json()}")

        # 2. correct captcha, wrong password
        cid, ans = await fresh_captcha()
        r = await c.post("/api/login", json={
            "code": "WRONG", "captcha_id": cid, "captcha": ans,
        })
        passed = r.status_code == 401
        ok &= passed
        print(f"2. wrong password  -> {r.status_code} {'PASS' if passed else 'FAIL'} {r.json()}")

        # 3. correct captcha + password -> session cookie (no second factor)
        cid, ans = await fresh_captcha()
        r = await c.post("/api/login", json={
            "code": PASSWORD, "captcha_id": cid, "captcha": ans,
        })
        passed = r.status_code == 200 and "access_token" in c.cookies
        ok &= passed
        print(f"3. both correct    -> {r.status_code} {'PASS' if passed else 'FAIL'} cookie={('access_token' in c.cookies)}")

        # 4. session cookie unlocks protected endpoints
        r = await c.get("/api/status")
        passed = r.status_code == 200
        ok &= passed
        print(f"4. status w/cookie -> {r.status_code} {'PASS' if passed else 'FAIL'}")

        # 5. captcha challenge cannot be reused
        cid, ans = await fresh_captcha()
        await c.post("/api/login", json={
            "code": "WRONG", "captcha_id": cid, "captcha": ans,
        })  # consumes the challenge
        r = await c.post("/api/login", json={
            "code": PASSWORD, "captcha_id": cid, "captcha": ans,
        })
        passed = r.status_code == 400
        ok &= passed
        print(f"5. captcha reuse   -> {r.status_code} {'PASS' if passed else 'FAIL'}")

    print()
    print("ALL TESTS PASSED" if ok else "SOME TESTS FAILED")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
