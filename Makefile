BIN_NAME ?= hyperion-network-watcher
BIN_DIR ?= bin
ENTRYPOINT = cmd/main.go

.PHONY: compile
compile:
	go build -o $(BIN_DIR)/$(BIN_NAME) $(ENTRYPOINT) 

.PHONY: run
run: compile
	HYPERION_CHILD=false sudo -E $(BIN_DIR)/$(BIN_NAME)