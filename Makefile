TARGET := mdns

CC 	= $(CROSS_PREFIX)gcc
RM := rm -f

PREPROC := _POSIX_C_SOURCE=200809L \
		  _BSD_SOURCE

CFLAGS  := -std=c99 -W -Wall -Wextra -Wformat=2 -Wno-unused-parameter -pipe -O3 -fstrict-aliasing -s

ifneq (, $(findstring mingw, $(CROSS_PREFIX)))
LDFLAGS = -lws2_32
SUFFIX := .exe
endif

SRC = mdns.c \
	  rr.c \
	  main.c \
	  compat.c \

OBJ = $(SRC:.c=.o)

all : $(TARGET)

$(TARGET) : $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET)$(SUFFIX) $(OBJ) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(addprefix -D, $(PREPROC)) -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJ)
