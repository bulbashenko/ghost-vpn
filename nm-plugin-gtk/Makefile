PLUGIN  = libnm-vpn-plugin-ghost.so
SRC     = ghost-nm-plugin.c

PKG     = libnm gtk+-3.0
CFLAGS  = -shared -fPIC -Wall -Wextra -Wno-unused-parameter \
          $(shell pkg-config --cflags $(PKG))
LIBS    = $(shell pkg-config --libs   $(PKG))

# Install path: NetworkManager looks in the multiarch NM lib dir.
NM_LIBDIR := /usr/lib/$(shell gcc -dumpmachine)/NetworkManager

.PHONY: all clean install

all: $(PLUGIN)

$(PLUGIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: $(PLUGIN)
	install -Dm755 $(PLUGIN) $(NM_LIBDIR)/$(PLUGIN)
	@echo "Installed to $(NM_LIBDIR)/$(PLUGIN)"

clean:
	rm -f $(PLUGIN)
