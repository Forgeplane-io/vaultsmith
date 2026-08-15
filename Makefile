SHELL := /bin/sh

.PHONY: test typecheck build smoke smoke-attestation compatibility helm-lint chart-test admission-benchmark admission-receipt-check docker release-check release-snapshot generate-api api-compat api-contract-test api-check

test:
	go test ./...

compatibility:
	go test -tags=ansible_cli ./backend/internal/ansiblevault -run 'TestCLI' -v

typecheck:
	npm run typecheck --prefix frontend

build:
	npm run build --prefix frontend
	go build ./...

generate-api:
	cd api && go tool oapi-codegen --config oapi-codegen.yaml openapi.yaml
	cd api && go run ./cmd/reference -input openapi.yaml -output ../docs/api-reference.md
	npm run generate --prefix api/typescript-generator

api-compat:
	./api/scripts/check-api-compatibility.sh

api-contract-test:
	python3 -m unittest discover -s api/scripts -p '*_test.py'

api-check: api-contract-test api-compat
	./api/scripts/check-generated.sh
	npm run typecheck --prefix api/typescript-generator
	go test ./backend/internal/apimodels

smoke:
	./scripts/smoke.sh

smoke-attestation:
	./scripts/smoke-attestation.sh

helm-lint:
	helm lint deploy/helm/vaultsmith -f deploy/helm/vaultsmith/tests/values-off.yaml

chart-test:
	bash deploy/helm/vaultsmith/tests/chart_test.sh

admission-benchmark:
	bash scripts/admission-benchmark.sh

admission-receipt-check:
	python3 -m unittest discover -s scripts -p 'check_admission_receipt_test.py'
	python3 scripts/check_admission_receipt.py

docker:
	docker build -t vaultsmith:local .

release-check:
	goreleaser check --config .goreleaser.yaml

release-snapshot:
	goreleaser release --config .goreleaser.yaml --snapshot --clean
