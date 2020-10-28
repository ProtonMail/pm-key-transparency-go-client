clean: ## Remove previous builds

install-linters:
	go install golang.org/x/lint/golint
	go install github.com/golangci/golangci-lint/cmd/golangci-lint

lint:
	golint -set_exit_status ./... && golangci-lint run ./...

test:
	go test ./... -count=1
