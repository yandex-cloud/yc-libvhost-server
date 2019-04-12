VHD_ROOT_DIR = $(abspath $(CURDIR)/../)
VHD_TARGET := libvirtio.a
include $(VHD_ROOT_DIR)/common.mk

$(VHD_TARGET): $(OBJS) $(HDRS)
	$(AR) rcs $@ $(OBJS)

clean:
	rm -f *.o $(VHD_TARGET)
	$(MAKE) -C test clean
