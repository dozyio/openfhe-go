# --- Variables ---
OPENFHE_SRC_DIR := $(CURDIR)/openfhe-development
OPENFHE_BUILD_DIR := $(CURDIR)/openfhe-build
OPENFHE_INSTALL_DIR := $(CURDIR)/openfhe-install

# Path to the marker file indicating OpenFHE install is complete
OPENFHE_INSTALL_MARKER := $(OPENFHE_INSTALL_DIR)/.installed

# Go build output name
GO_APP_NAME := go_simple_integers

# OpenFHE Git repository and tag/branch (use a specific tag for stability)
OPENFHE_REPO := https://github.com/openfheorg/openfhe-development.git
OPENFHE_TAG := v1.4.2

# CMake options for OpenFHE
# - Build statically
# - Install locally within the project
# - Add other options as needed (e.g., -DWITH_NATIVEOPT=ON for performance)
CMAKE_OPTIONS := -DBUILD_SHARED=OFF \
                 -DBUILD_STATIC=ON \
                 -DCMAKE_INSTALL_PREFIX=$(OPENFHE_INSTALL_DIR) \
                 -DBUILD_EXAMPLES=OFF \
                 -DBUILD_UNITTESTS=OFF \
                 -DBUILD_BENCHMARKS=OFF \
                 -DCMAKE_BUILD_TYPE=Release \
                 -DWITH_OPENMP=OFF # Disable OpenMP if not needed/causing issues

# --- Targets ---

.PHONY: all build run clean fetch_openfhe build_openfhe clean_openfhe

# Default target: build the Go application
all: build

# Target to ensure OpenFHE is fetched and installed
$(OPENFHE_INSTALL_MARKER): $(OPENFHE_SRC_DIR)/CMakeLists.txt
	@echo "--- Ensuring build directory exists and CMake cache is cleared ---"
	@mkdir -p $(OPENFHE_BUILD_DIR)
	@rm -f $(OPENFHE_BUILD_DIR)/CMakeCache.txt
	@echo "--- Configuring OpenFHE ---"
	@mkdir -p $(OPENFHE_BUILD_DIR)
	cd $(OPENFHE_BUILD_DIR) && cmake $(CMAKE_OPTIONS) $(OPENFHE_SRC_DIR)
	@echo "--- Building OpenFHE (this may take a while) ---"
	@cmake --build $(OPENFHE_BUILD_DIR) --parallel $$(nproc)
	@echo "--- Installing OpenFHE ---"
	@cmake --install $(OPENFHE_BUILD_DIR)
	@touch $(OPENFHE_INSTALL_MARKER) # Create marker file upon success

# Target to fetch OpenFHE source code
$(OPENFHE_SRC_DIR)/CMakeLists.txt:
	@if [ ! -d "$(OPENFHE_SRC_DIR)" ]; then \
		echo "--- Cloning OpenFHE repository ($(OPENFHE_TAG)) ---"; \
		git clone --depth 1 --branch $(OPENFHE_TAG) $(OPENFHE_REPO) $(OPENFHE_SRC_DIR); \
	else \
		echo "--- OpenFHE directory already exists. Checking tag... ---"; \
		cd $(OPENFHE_SRC_DIR) && \
		CURRENT_TAG=$$(git describe --tags --exact-match 2>/dev/null) && \
		if [ "$$CURRENT_TAG" != "$(OPENFHE_TAG)" ]; then \
			echo "Warning: OpenFHE directory exists but is not on tag $(OPENFHE_TAG)."; \
			echo "Current state: $$CURRENT_TAG / $$(git rev-parse --abbrev-ref HEAD)"; \
			echo "To fetch the correct version, run 'make clean_openfhe' then 'make build_openfhe'."; \
		else \
			echo "OpenFHE is on the correct tag ($(OPENFHE_TAG))."; \
		fi; \
	fi

# Explicit target to build OpenFHE (depends on fetching)
build_openfhe: $(OPENFHE_INSTALL_MARKER)
	@echo "--- OpenFHE build and install complete ---"

test: $(OPENFHE_INSTALL_MARKER)
	@go test -v -count 1 ./openfhe

# Targets to run the examples
run-bfv-example: $(OPENFHE_INSTALL_MARKER)
	@echo "--- Running BFV (Integers) Example ---"
	@go run ./examples/simple-integers/main.go

run-ckks-example: $(OPENFHE_INSTALL_MARKER)
	@echo "--- Running CKKS (Real Numbers) Example ---"
	@go run ./examples/simple-real-numbers/main.go

# Target to clean Go build artifacts
clean:
	@echo "--- Cleaning Go build artifacts ---"
	@rm -f $(GO_APP_NAME)
	@go clean

# Target to clean OpenFHE build and install directories
clean_openfhe:
	@echo "--- Cleaning OpenFHE build and install directories ---"
	@rm -rf $(OPENFHE_BUILD_DIR) $(OPENFHE_INSTALL_DIR) $(OPENFHE_SRC_DIR)
