ccflags-$(CONFIG_PPC_WERROR)	+= -Werror

ocxl-y				+= main.o pci.o config.o file.o pasid.o
ocxl-y				+= context.o sysfs.o trace.o
ocxl-$(CONFIG_PPC_POWERNV)	+= spa.o
obj-$(CONFIG_OCXL)		+= ocxl.o

# For tracepoints to include our trace.h from tracepoint infrastructure:
CFLAGS_trace.o := -I$(src)
