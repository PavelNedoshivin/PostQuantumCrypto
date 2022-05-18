#include "Launcher.hpp"

int main() {
	return (runClassicMcEliece() || runCrystalsKyber() || runNTRU() || runSaber());
}