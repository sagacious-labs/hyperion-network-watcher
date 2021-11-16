BIN_NAME ?= hyperion-network-watcher
BIN_DIR ?= bin
ENTRYPOINT = cmd/main.go

.PHONY: run
run: compile setup-ebpf
	HYPERION_CHILD=false sudo -E $(BIN_DIR)/$(BIN_NAME)

.PHONY: hyper-run
hyper-run: compile setup-ebpf
	sudo -E $(BIN_DIR)/$(BIN_NAME)

.PHONY: setup-ebpf
setup-ebpf:
	sudo mkdir -p /usr/share/hyperion/tools/tcp && \
	sudo cp ./ebpf/* /usr/share/hyperion/tools/tcp/

.PHONY: compile
compile:
	go build -o $(BIN_DIR)/$(BIN_NAME) $(ENTRYPOINT)