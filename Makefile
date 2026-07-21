# sstp_client — pure-Dart SSTP CLI: dev/run helpers.
#
# Unlike the Flutter apps, this is a plain CLI, so there is no bundle or
# privilege wrapper. Two ways to run it:
#
#   make handshake HOST=1.2.3.4          # connect + PPP handshake only (no tunnel,
#                                        #   no privilege) — a quick reachability test
#   make tunnel HOST=1.2.3.4             # bring the TUN device up and route traffic;
#                                        #   needs privilege, so it runs under sudo
#
# The tunnel path compiles to a self-contained exe and runs it with sudo (root
# inherits CAP_NET_ADMIN for both the TUNSETIFF ioctl and the `ip` subprocess —
# no setcap/wrapper needed for a CLI).
#
# Connection parameters (override on the command line).
# Note: not named USER/PASS — `USER` is a shell env var that would shadow a `?=`
# default, so the VPN credentials use distinct names.
HOST    ?=
PORT    ?= 443
VPNUSER ?= vpn
VPNPASS ?= vpn
ROUTE   ?= full
# Extra flags appended verbatim, e.g.  make handshake HOST=1.2.3.4 ARGS=-v
ARGS    ?=

EXE  := sstp
DART := $(shell command -v dart)

CONN_ARGS := --host "$(HOST)" --port "$(PORT)" --username "$(VPNUSER)" --password "$(VPNPASS)" $(ARGS)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "sstp_client — make targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'
	@echo "  params: HOST= PORT=$(PORT) VPNUSER=$(VPNUSER) VPNPASS=$(VPNPASS) ROUTE=$(ROUTE) ARGS="

.PHONY: handshake
handshake: require-host ## Connect + PPP handshake only (no tunnel, no privilege)
	$(DART) run bin/main.dart $(CONN_ARGS)

.PHONY: tunnel
tunnel: require-host compile ## Bring up the TUN device and route traffic (runs sudo)
	sudo ./$(EXE) --tunnel --route-mode $(ROUTE) $(CONN_ARGS)

.PHONY: compile
compile: ## Compile the CLI to a self-contained ./sstp executable
	$(DART) compile exe bin/main.dart -o $(EXE)

.PHONY: test
test: ## Run the test suite
	$(DART) test

.PHONY: analyze
analyze: ## Static analysis
	$(DART) analyze

.PHONY: get
get: ## Fetch dependencies
	$(DART) pub get

.PHONY: clean
clean: ## Remove the compiled executable
	rm -f $(EXE)

.PHONY: require-host
require-host:
	@test -n "$(HOST)" || { echo "error: set HOST=<server ip/host>, e.g. make tunnel HOST=1.2.3.4" >&2; exit 1; }
