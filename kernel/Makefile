TARGET_LIBS=libSceStdioTMP_KERNEL_stub.a libSceKernelThreadMgrTMP_KERNEL_stub.a libSceSysmemTMP_KERNEL_stub.a libSceKernelModulemgrTMP_KERNEL_stub.a

all: $(TARGET_LIBS)

$(TARGET_LIBS): build_stubs
	mv build_lib/$(subst TMP_KERNEL,,$@) $(PREFIX)/$@

build_stubs: kernel.json
	-rm -rf build_lib
	mkdir build_lib
	vita-libs-gen $< build_lib
	cd build_lib && make && cd ..

clean:
	-rm -rf build_lib
	rm $(TARGET_LIBS)
