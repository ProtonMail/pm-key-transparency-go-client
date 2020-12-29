LINTERS_VERSION=v1.32.0

install-linters:
	go install golang.org/x/lint/golint
	GO111MODULE=on go get github.com/golangci/golangci-lint/cmd/golangci-lint@$(LINTERS_VERSION)

lint:
	golint -set_exit_status ./... && golangci-lint run ./...

test:
	go test ./... -count=1 -v

bench:
	go test -bench=.
