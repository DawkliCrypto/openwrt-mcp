ROUTER ?= root@192.168.0.2
GO     ?= /usr/local/go/bin/go
ARCH   ?= arm64

# OpenWrt's dropbear has no sftp-server, so modern scp (which defaults to SFTP)
# fails with "Connection closed". Pipe over ssh instead.
DEPLOY = ssh $(ROUTER) 'cat > $(1) && chmod +x $(1)'

test:
	$(GO) vet ./... && $(GO) test ./...

build: test
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -ldflags="-s -w" -o openwrt-mcp.$(ARCH) .

install: build
	$(call DEPLOY,/usr/bin/openwrt-mcp) < openwrt-mcp.$(ARCH)
	ssh $(ROUTER) 'cat > /etc/init.d/openwrt-mcp && chmod +x /etc/init.d/openwrt-mcp' < files/etc/init.d/openwrt-mcp
	ssh $(ROUTER) '[ -f /etc/config/openwrt-mcp ] || cat > /etc/config/openwrt-mcp' < files/etc/config/openwrt-mcp
	ssh $(ROUTER) '/etc/init.d/openwrt-mcp enable && /etc/init.d/openwrt-mcp restart && sleep 1 && logread -l 5 | grep openwrt-mcp'

# Staging install for testing: /tmp only, nothing persisted.
stage: build
	$(call DEPLOY,/tmp/openwrt-mcp) < openwrt-mcp.$(ARCH)

clean:
	rm -f openwrt-mcp openwrt-mcp.*

.PHONY: test build install stage clean
