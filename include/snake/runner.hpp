#pragma once

#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::runner {

enum class Mode { kHelp, kList, kExec };

struct Parsed {
    Mode mode = Mode::kHelp;
    std::string name;
    payloads::Args args;
};

std::string banner();
std::string help_text();

Parsed parse_args(const std::vector<std::string>& argv);

int runner_main(int argc, char** argv);

}  // namespace snake::runner
