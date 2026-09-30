"""Generate steady traffic against the tester so dashboards and alerts have data.

  python scripts/loadgen.py --base http://localhost:8000 --rps 5 --duration 300
"""
import argparse
import asyncio
import random
import time

import httpx

CALLS = [
    (5, "GET", "/api/me", None),
    (2, "GET", "/api/debug-token", None),
    (3, "GET", "/api/pages/posts?limit=5", None),
    (2, "GET", "/api/instagram/media?limit=5", None),
    (4, "POST", "/api/whatsapp/messages", {"to": "15551234567", "text": "load test"}),
    (1, "POST", "/api/pages/posts", {"message": "load test post"}),
    (1, "GET", "/api/graph/1234567890?fields=name,followers_count", None),
]


async def main(base: str, rps: float, duration: float) -> None:
    weights = [c[0] for c in CALLS]
    stats: dict[int, int] = {}
    deadline = time.monotonic() + duration
    async with httpx.AsyncClient(base_url=base, timeout=60) as client:
        async def one():
            _, method, path, body = random.choices(CALLS, weights)[0]
            if body and "to" in body:   # spread recipients, like real traffic (pair rate limit is per user)
                body = {**body, "to": f"1555{random.randint(0, 999999):06d}"}
            try:
                r = await client.request(method, path, json=body)
                stats[r.status_code] = stats.get(r.status_code, 0) + 1
            except httpx.HTTPError:
                stats[-1] = stats.get(-1, 0) + 1

        tasks = set()
        while time.monotonic() < deadline:
            t = asyncio.create_task(one())
            tasks.add(t)
            t.add_done_callback(tasks.discard)
            await asyncio.sleep(1 / rps)
            if int(time.monotonic()) % 10 == 0:
                print("status counts:", dict(sorted(stats.items())), flush=True)
        await asyncio.gather(*tasks)
    print("final:", dict(sorted(stats.items())))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8000")
    p.add_argument("--rps", type=float, default=5)
    p.add_argument("--duration", type=float, default=300)
    a = p.parse_args()
    asyncio.run(main(a.base, a.rps, a.duration))
