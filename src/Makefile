#
# $Header$
#

CFILENAMES = wifidog.c

OFILENAMES = wifidog.o

CFLAGS += -Os -Wall

all: wifidog

wifidog: $(OFILENAMES)
	$(CC) $(CFLAGS) $(OFILENAMES) -o $@
	strip $@

$(OFILENAMES): $(CFILENAMES)
	$(CC) -c $(CFLAGS) $<

clean:
	for filename in $(OFILENAMES) wifidog; do \
		if [ -f $$filename ]; then $(RM) $$filename; fi \
	done
