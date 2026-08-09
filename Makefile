SHELL := /bin/sh

.PHONY: test typecheck build smoke compatibility helm-lint chart-test docker release-check release-snapshot

test:
	go test ./...

compatibility:
	go test -tags=ansible_cli ./backend/internal/ansiblevault -run 'TestCLI' -v

typecheck:
	npm run typecheck --prefix frontend

build:
	npm run build --prefix frontend
	go build ./...

smoke:
	./scripts/smoke.sh

helm-lint:
	helm lint deploy/helm/vaultsmith -f deploy/helm/vaultsmith/tests/values-off.yaml

chart-test:
	bash deploy/helm/vaultsmith/tests/chart_test.sh

docker:
	docker build -t vaultsmith:local .

release-check:
	goreleaser check --config .goreleaser.yaml

release-snapshot:
	goreleaser release --config .goreleaser.yaml --snapshot --clean
