all: protocol opensnitch_daemon gui ebpf-all

ebpf-all:
	@cd ebpf_prog && make all

install:
	@cd daemon && make install
	@cd ui && make install
	@cd ebpf && make install

protocol:
	@cd proto && make

opensnitch_daemon:
	@cd daemon && make

gui:
	@cd ui && make

clean:
	@cd daemon && make clean
	@cd proto && make clean
	@cd ui && make clean
	@cd ebpf_prog && make clean

run:
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock -cpu-profile cpu.profile -mem-profile mem.profile

run-gui:
	opensnitch-ui --socket unix:///tmp/osui.sock

test: 
	clear 
	make clean
	clear
	mkdir -p rules
	make 
	clear
	make run

adblocker:
	clear 
	make clean
	clear
	make 
	clear
	python3 ./utils/legacy/make_ads_rules.py
	clear
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock


