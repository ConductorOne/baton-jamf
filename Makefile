GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)
BUILD_DIR = dist/${GOOS}_${GOARCH}
GENERATED_CONF := pkg/config/conf.gen.go

ifeq ($(GOOS),windows)
OUTPUT_PATH = ${BUILD_DIR}/baton-jamf.exe
else
OUTPUT_PATH = ${BUILD_DIR}/baton-jamf
endif

.PHONY: build
build: $(GENERATED_CONF)
	go build -o ${OUTPUT_PATH} ./cmd/baton-jamf

$(GENERATED_CONF): pkg/config/schema.go go.mod
	@echo "Generating $(GENERATED_CONF)..."
	go generate ./pkg/config

.PHONY: generate
generate: $(GENERATED_CONF)

.PHONY: update-deps
update-deps:
	go get -d -u ./...
	go mod tidy -v
	go mod vendor

.PHONY: add-dep
add-dep:
	go mod tidy -v
	go mod vendor

.PHONY: lint
lint:
	golangci-lint run
