BPF_OBJ_NAME = fentry_bpf

CONFIG_CREATE=y
CONFIG_DELETE=y
CONFIG_MODIFY=y
CONFIG_RENAME=y


export CONFIG_CREATE
export CONFIG_DELETE
export CONFIG_MODIFY
export CONFIG_RENAME

all:
	@echo "Building eBPF program"
	cd src/bpf && $(MAKE) && cd ../..
	@echo "Building user space program"
	cd src/user && $(MAKE) && cd ../..


clean:
	cd src/bpf && $(MAKE) clean && cd ../..
	cd src/user && $(MAKE) clean && cd ../..


.PHONY: all
