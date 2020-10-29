install-linters:
	go install golang.org/x/lint/golint@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

lint:
	golangci-lint run ./...

test:
	go test ./... -count=1 -v

bench:
	go test -bench=.
