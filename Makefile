TARGET	:= libmdns

CC		:= $(CROSS_COMPILE)gcc
RM		:= rm -f

PREPROC := _POSIX_C_SOURCE=200809L _BSD_SOURCE

LDFLAGS	:= -shared -s
CFLAGS  := -std=c99 -Wall -Wextra -Wformat=2 -Wno-unused-parameter -pipe -O3 -fstrict-aliasing \
		   -Wcast-align -Wpointer-arith -Wmissing-prototypes -Wwrite-strings -Wlogical-op

SRC 	:= mdns.c rr.c compat.c
OBJ		:= $(SRC:.c=.o)

ifneq (, $(findstring mingw, $(CROSS_COMPILE)))

LDFLAGS	+= $(TARGET).def -lws2_32
SUFFIX	:= .dll
BIN 	:= mdns.exe

else

CFLAGS	+= -fPIC
LDFLAGS += -Wl,-z,relro -Wl,-z,now -Wl,-O1 -Wl,--version-script=$(TARGET).version
SUFFIX	:= .so
BIN 	:= mdns

endif

all : $(TARGET)

$(TARGET) : $(OBJ)
	$(CC) -o $(TARGET)$(SUFFIX) $(OBJ) $(LDFLAGS)

.c.o :
	$(CC) $(CFLAGS) $(addprefix -D, $(PREPROC)) -c -o $@ $<

test : $(TARGET)
	$(CC) -o $(BIN) main.c -L. -l$(subst lib,,$(TARGET)) -s

clean :
	$(RM) $(TARGET)$(SUFFIX) $(OBJ) $(BIN)
