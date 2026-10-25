.PHONY: test build compose-check

test:
	go test ./...

build:
	go build ./cmd/redactthis

compose-check:
	@for env in deploy/cpu.env deploy/nvidia.env deploy/rocm.env deploy/intel.env; do \
		docker compose --env-file $$env config --quiet; \
	done

