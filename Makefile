# Shortcuts for the most common commands. Run `make help`.
.PHONY: help install test lint demo serve train up down logs attack k8s-local tf-plan

help:            ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

install:         ## install Aegis + dev tools into the current Python environment
	pip install -e ".[infra,dev]"

lint:            ## ruff linter
	ruff check src tests

test:            ## run the test suite
	pytest -q

train:           ## train + evaluate ML models (writes ml/reports/)
	aegis train

demo:            ## whole pipeline in one process, print the incident report
	aegis demo --scenario all

serve:           ## demo + dashboard on http://localhost:8000 with live traffic
	aegis demo --scenario all --serve --live --attack-every 300

up:              ## full stack with Kafka, Postgres, Redis, S3, Prometheus, Grafana, Jaeger
	docker compose up -d --build

down:            ## stop the stack and delete its data
	docker compose down -v

logs:            ## follow the logs of the Aegis services
	docker compose logs -f collector auth-analyzer cloud-analyzer network-analyzer ml-inference correlator investigator

attack:          ## inject the flagship attack into the running stack
	curl -s -X POST localhost:8000/api/simulate/credential_compromise

k8s-local:       ## deploy to a local kind cluster
	docker build -t aegis:local .
	kind create cluster --name aegis || true
	kind load docker-image aegis:local --name aegis
	kubectl apply -k deploy/k8s/overlays/local

tf-plan:         ## terraform plan for AWS (needs AWS credentials)
	cd deploy/terraform && terraform init && terraform plan
