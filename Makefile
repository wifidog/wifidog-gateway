#
# $Header$
#

SUBFOLDERS = src

all:
	for target in $(SUBFOLDERS); do \
		$(MAKE) -C $$target; \
	done

clean:
	for target in $(SUBFOLDERS); do \
		$(MAKE) -C $$target clean; \
	done

