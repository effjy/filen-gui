# Filen GUI - Makefile
# Build:     make
# Install:   sudo make install
# Uninstall: sudo make uninstall

APP        := filen-gui
APP_ID     := io.github.jflc.FilenGUI
PREFIX     ?= /usr/local
BINDIR     := $(PREFIX)/bin
DATADIR    := $(PREFIX)/share
DESKTOPDIR := $(DATADIR)/applications
ICONDIR    := $(DATADIR)/icons/hicolor/scalable/apps

CXX      ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra
CXXFLAGS += $(shell pkg-config --cflags gtk4 libcurl libcrypto libargon2)
LIBS     := $(shell pkg-config --libs gtk4 libcurl libcrypto libargon2) -lpthread

SRC := src/main.cpp src/filen_client.cpp src/crypto.cpp
OBJ := $(SRC:.cpp=.o)

.PHONY: all clean install uninstall

all: $(APP)

$(APP): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(APP)

install: $(APP)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(APP) $(DESTDIR)$(BINDIR)/$(APP)
	install -d $(DESTDIR)$(DESKTOPDIR)
	install -m 644 data/$(APP_ID).desktop $(DESTDIR)$(DESKTOPDIR)/$(APP_ID).desktop
	install -d $(DESTDIR)$(ICONDIR)
	install -m 644 data/$(APP_ID).svg $(DESTDIR)$(ICONDIR)/$(APP_ID).svg
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESKTOPDIR) 2>/dev/null || true
	@echo "Installed $(APP). You should now see it in your applications menu."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(APP)
	rm -f $(DESTDIR)$(DESKTOPDIR)/$(APP_ID).desktop
	rm -f $(DESTDIR)$(ICONDIR)/$(APP_ID).svg
	-gtk-update-icon-cache -f -t $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESKTOPDIR) 2>/dev/null || true
	@echo "Uninstalled $(APP)."
