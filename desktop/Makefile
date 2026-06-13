# Dependency-free build (embedded server + UI; opens the system browser).
# For the native-window build, use CMake with -DAEGIS_WITH_WEBVIEW=ON (see README).
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -pthread -I third_party -I src
WEB      := $(wildcard web/* web/assets/*)

aegis-desktop: src/assets_generated.h src/main.cpp
	$(CXX) $(CXXFLAGS) src/main.cpp -o $@

src/assets_generated.h: $(WEB) tools/embed_assets.py
	python3 tools/embed_assets.py web src/assets_generated.h

run: aegis-desktop
	./aegis-desktop

clean:
	rm -f aegis-desktop

.PHONY: run clean
