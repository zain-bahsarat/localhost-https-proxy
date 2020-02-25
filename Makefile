.ONESHELL: ; # recipes execute in same shell
.NOTPARALLEL: ; # wait for this target to finish
.EXPORT_ALL_VARIABLES: ; # send all vars to shell

.PHONY: all help build format lint  clean 
.DEFAULT: help


GOFILES :=$(shell go list ./... | grep -v /vendor/)
BUILD_FILE := "https-proxy"


help: ## Show Help
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deps: ## Install Dependencies
	@go get github.com/mgechev/revive && \
	go get github.com/zain-bahsarat/minica && \
	go mod tidy

build: ## Build
	@go build -ldflags '-w -s' -o $(BUILD_FILE)

format: ## Format using go fmt
	@go fmt $(GOFILES)

lint: ## lint 
	@go vet $(GOFILES)
	@revive -config revive.toml -formatter friendly $(GOFILES)
clean: ##removes the build
	@rm -rf main