TARGET := mdns

CC 	= $(CROSS_PREFIX)gcc
RM := rm -f

PREPROC = _POSIX_C_SOURCE=200809L \
		  _BSD_SOURCE

CFLAGS  = -std=c99 -W -Wall -Wextra -Wformat=2 -Wno-unused-parameter -pipe -O3 -fstack-protector -s

SRC = mdns.c \
	  rr.c \
	  main.c \

OBJ = $(SRC:.c=.o)

all : $(TARGET)

$(TARGET) : $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

.c.o:
	$(CC) $(CFLAGS) $(addprefix -D, $(PREPROC)) -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJ)
