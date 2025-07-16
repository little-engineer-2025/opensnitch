#SRC contains all *.go *.c *.h files in daemon/ and its subfolders 
SRC := $(shell find . -type f -name '*.go' -o -name '*.h' -o -name '*.c')
PREFIX?=/usr/local

.PHONY: all
all: opensnitchd

.PHONY: install
install:
	@mkdir -p $(DESTDIR)/etc/opensnitchd/rules
	@install -Dm755 opensnitchd \
		-t $(DESTDIR)$(PREFIX)/bin/
	@install -Dm644 opensnitchd.service \
		-t $(DESTDIR)/etc/systemd/system/
	@install -Dm644 default-config.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@install -Dm644 system-fw.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@install -Dm644 network_aliases.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@systemctl daemon-reload
	@systemctl enable opensnitchd.service
	@systemctl start opensnitchd.service

opensnitchd: $(SRC)
	@go get
	@go build -o opensnitchd .

.PHONY: clean
clean:
	@rm -rf opensnitchd

.PHONY: test
test:
	go test -parallel 4 -coverprofile="coverage.out.tmp" -covermode count $(shell go list ./...)
	grep -v -e '.pb.go' coverage.out.tmp > coverage.out
	rm coverage.out.tmp

coverage.out: test

.PHONY: coverage
coverage: coverage.out
	go tool cover -func ./coverage.out
