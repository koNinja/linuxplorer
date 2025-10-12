#include <clocale>
#include "commands.hpp"

int main(int argc, char** argv) {
	std::setlocale(LC_ALL, "");

	return linuxplorer::app::linuxplorer::option_handler(argc, argv);
}