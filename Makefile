# --- Variables ---
OPENFHE_SRC_DIR := $(CURDIR)/openfhe-development
OPENFHE_BUILD_DIR := $(CURDIR)/openfhe-build
OPENFHE_INSTALL_DIR := $(CURDIR)/openfhe-install

# Path to the marker file indicating OpenFHE install is complete
# Separate markers for shared and static builds
OPENFHE_SHARED_MARKER := $(OPENFHE_INSTALL_DIR)/.installed-shared
OPENFHE_STATIC_MARKER := $(OPENFHE_INSTALL_DIR)/.installed-static

# Go build output name
GO_APP_NAME := go_simple_integers

# OpenFHE Git repository and tag/branch (use a specific tag for stability)
OPENFHE_REPO := https://github.com/openfheorg/openfhe-development.git
OPENFHE_TAG := v1.4.2

# Base CMake options for OpenFHE
CMAKE_BASE_OPTIONS := -DCMAKE_INSTALL_PREFIX=$(OPENFHE_INSTALL_DIR) \
                      -DBUILD_EXAMPLES=OFF \
                      -DBUILD_UNITTESTS=OFF \
                      -DBUILD_BENCHMARKS=OFF \
                      -DWITH_NATIVEOPT=OFF \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DWITH_OPENMP=OFF

# Shared library options (default for development)
CMAKE_SHARED_OPTIONS := $(CMAKE_BASE_OPTIONS) \
                        -DBUILD_SHARED=ON \
                        -DBUILD_STATIC=OFF

# Static library options (for production builds)
CMAKE_STATIC_OPTIONS := $(CMAKE_BASE_OPTIONS) \
                        -DBUILD_SHARED=OFF \
                        -DBUILD_STATIC=ON

# --- Targets ---

.PHONY: all build build-static run clean fetch_openfhe build_openfhe build_openfhe_shared build_openfhe_static clean_openfhe test test-coverage benchmark

# Default target: build with shared libraries (fast for development)
all: build

# Target to build OpenFHE with shared libraries (default for dev)
$(OPENFHE_SHARED_MARKER): $(OPENFHE_SRC_DIR)/CMakeLists.txt
	@echo "--- Building OpenFHE with SHARED libraries (development mode) ---"
	@mkdir -p $(OPENFHE_BUILD_DIR)
	@rm -f $(OPENFHE_BUILD_DIR)/CMakeCache.txt
	@echo "--- Configuring OpenFHE (shared) ---"
	cd $(OPENFHE_BUILD_DIR) && cmake $(CMAKE_SHARED_OPTIONS) $(OPENFHE_SRC_DIR)
	@echo "--- Building OpenFHE (this may take a while) ---"
	@cmake --build $(OPENFHE_BUILD_DIR) --parallel $$(sysctl -n hw.ncpu)
	@echo "--- Installing OpenFHE ---"
	@cmake --install $(OPENFHE_BUILD_DIR)
	@touch $(OPENFHE_SHARED_MARKER)
	@rm -f $(OPENFHE_STATIC_MARKER) # Remove static marker if exists

# Target to build OpenFHE with static libraries (for production)
$(OPENFHE_STATIC_MARKER): $(OPENFHE_SRC_DIR)/CMakeLists.txt
	@echo "--- Building OpenFHE with STATIC libraries (production mode) ---"
	@mkdir -p $(OPENFHE_BUILD_DIR)
	@rm -f $(OPENFHE_BUILD_DIR)/CMakeCache.txt
	@echo "--- Configuring OpenFHE (static) ---"
	cd $(OPENFHE_BUILD_DIR) && cmake $(CMAKE_STATIC_OPTIONS) $(OPENFHE_SRC_DIR)
	@echo "--- Building OpenFHE (this may take a while) ---"
	@cmake --build $(OPENFHE_BUILD_DIR) --parallel $$(sysctl -n hw.ncpu)
	@echo "--- Installing OpenFHE ---"
	@cmake --install $(OPENFHE_BUILD_DIR)
	@touch $(OPENFHE_STATIC_MARKER)
	@rm -f $(OPENFHE_SHARED_MARKER) # Remove shared marker if exists

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

# Explicit target to build OpenFHE with shared libraries (default)
build_openfhe: build_openfhe_shared

build_openfhe_shared: $(OPENFHE_SHARED_MARKER)
	@echo "--- OpenFHE shared library build complete ---"

build_openfhe_static: $(OPENFHE_STATIC_MARKER)
	@echo "--- OpenFHE static library build complete ---"

# Build the Go package with shared libraries (fast development builds)
build: $(OPENFHE_SHARED_MARKER)
	@echo "Building Go package with shared libraries (development mode)..."
	@echo "Note: Shared libraries are in $(OPENFHE_INSTALL_DIR)/lib"
	CGO_LDFLAGS_ALLOW=".*" go build ./...

# Build the Go package with static libraries (production builds)
build-static: $(OPENFHE_STATIC_MARKER)
	@echo "Building Go package with static libraries (production mode)..."
	CGO_LDFLAGS_ALLOW=".*" OPENFHE_STATIC=1 go build ./...

test: $(OPENFHE_SHARED_MARKER)
	@echo "Running Go tests..."
	CGO_LDFLAGS_ALLOW=".*" go test -v -count 1 ./openfhe

test-coverage: $(OPENFHE_SHARED_MARKER)
	@echo "Running Go tests with coverage..."
	CGO_LDFLAGS_ALLOW=".*" go test -v -count 1 -coverprofile=coverage.out ./openfhe
	@echo "\n--- Coverage Summary ---"
	@go tool cover -func=coverage.out | tail -1
	@echo "\nGenerating HTML coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-short: $(OPENFHE_SHARED_MARKER)
	@echo "Running Go tests (short mode, skips slow tests)..."
	CGO_LDFLAGS_ALLOW=".*" go test -v -short -count 1 ./openfhe

benchmark: $(OPENFHE_SHARED_MARKER)
	@echo "Running benchmarks..."
	CGO_LDFLAGS_ALLOW=".*" go test -bench=. -benchmem -count 3 ./openfhe

run-examples: $(OPENFHE_SHARED_MARKER)
	@echo "Running all Go examples..."
	@find ./examples -type f -name 'main.go' -execdir sh -c 'echo "\n▶ running $$(pwd)/$$1"; CGO_LDFLAGS_ALLOW=".*" go run . ' _ {} \;

# Target to clean Go build artifacts
clean:
	@echo "--- Cleaning Go build artifacts ---"
	@rm -f $(GO_APP_NAME)
	@rm -f coverage.out coverage.html
	@go clean

# Target to clean OpenFHE build and install directories
clean_openfhe:
	@echo "--- Cleaning OpenFHE build and install directories ---"
	@rm -rf $(OPENFHE_BUILD_DIR) $(OPENFHE_INSTALL_DIR) $(OPENFHE_SRC_DIR)
