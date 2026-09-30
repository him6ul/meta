.PHONY: scale contract token-status delivery-stats verify-last install test run mock up down load chaos-errors chaos-outage chaos-throttle chaos-reset webhook audit audit-verify slack audit-verify-s3 audit-archive-ls audit-archive-reset-local

install:
	python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest -q

run:        ## run the app locally against whatever META_GRAPH_BASE_URL is in .env
	.venv/bin/uvicorn app.main:app --reload --port 8000

mock:       ## run the mock Meta server locally
	.venv/bin/uvicorn mock_meta.server:app --port 8081

up:
	docker compose up -d --build

down:
	docker compose down

load:
	docker compose --profile load up -d loadgen

chaos-errors:
	curl -s -XPOST localhost:8081/_mock/config -H "x-actor: $${USER}" -H 'content-type: application/json' -d '{"error_rate":0.3}'

chaos-throttle:
	curl -s -XPOST localhost:8081/_mock/config -H "x-actor: $${USER}" -H 'content-type: application/json' -d '{"throttle_rate":0.4}'

chaos-outage:
	curl -s -XPOST localhost:8081/_mock/config -H "x-actor: $${USER}" -H 'content-type: application/json' -d '{"outage":true}'

chaos-reset:
	curl -s -XPOST localhost:8081/_mock/config -H "x-actor: $${USER}" -H 'content-type: application/json' -d '{"outage":false,"error_rate":0.02,"throttle_rate":0.02,"auth_error_rate":0}'

webhook:
	curl -s -XPOST localhost:8081/_mock/send-webhook

audit:      ## latest 20 audit records
	curl -s 'localhost:8000/api/audit?limit=20' -H "x-api-key: $${API_KEY}" | python3 -m json.tool

audit-verify:
	curl -s localhost:8000/api/audit/verify -H "x-api-key: $${API_KEY}"

slack:      ## messages received by the fake Slack endpoint
	curl -s localhost:8081/_mock/slack | python3 -m json.tool

audit-verify-s3:   ## verify the S3 Object Lock archive end-to-end and against the local log
	docker compose exec -T audit-gateway sh -c 'python -m app.audit_gateway verify --compare-local /replicas/audit-*.jsonl'

audit-archive-ls:
	docker compose exec -T localstack awslocal s3api list-object-versions --bucket meta-audit-local \
	  --prefix audit/meta-api-tester/blocks/ --query '{versions: Versions[].[Key,Size], delete_markers: DeleteMarkers[].[Key,VersionId]}'

audit-archive-reset-local:   ## LocalStack only: wipe the ephemeral archive and the gateway index
	docker compose rm -sf localstack audit-gateway && docker volume rm -f meta_gateway-state && docker compose up -d

contract:   ## live contract tests against the real Meta API (needs META_LIVE_* env; see tests/contract)
	.venv/bin/pytest -m live tests/contract -v

token-status:
	curl -s 'localhost:8000/api/token-status?refresh=true' | python3 -m json.tool

delivery-stats:
	curl -s localhost:8000/api/whatsapp/delivery-stats | python3 -m json.tool

verify-last:   ## latest scheduled archive verification (runs in the gateway every AUDIT_VERIFY_INTERVAL_SECONDS)
	docker compose exec -T audit-gateway python -c "import urllib.request as u;print(u.urlopen('http://localhost:9102/verify/last').read().decode())" | python3 -m json.tool

scale:   ## run N app replicas behind the load balancer, e.g. make scale N=4
	docker compose up -d --scale app=$${N:-3} --no-recreate
