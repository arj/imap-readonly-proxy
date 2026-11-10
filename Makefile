GO ?= go

.PHONY: build test fuzz e2e vet
build:
	$(GO) build -trimpath -o bin/imap-readonly-proxy ./cmd/imap-readonly-proxy
vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./...
test:
	$(GO) test -race ./...
fuzz:
	$(GO) test ./internal/policy -run '^$$' -fuzz FuzzPolicy -fuzztime $${FUZZTIME:-60s}
	$(GO) test ./internal/restapi -run '^$$' -fuzz '^FuzzParseResponse$$' -fuzztime $${FUZZTIME_SHORT:-20s}
	$(GO) test ./internal/restapi -run '^$$' -fuzz '^FuzzParseMessage$$' -fuzztime $${FUZZTIME_SHORT:-20s}
	$(GO) test ./internal/restapi -run '^$$' -fuzz '^FuzzMailboxUTF7$$' -fuzztime $${FUZZTIME_SHORT:-20s}
e2e:
	./test/e2e/run.sh
