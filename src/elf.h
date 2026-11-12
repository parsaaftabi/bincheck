#pragma once

#include "reader.h"
#include "report.h"

Report parseElf(const Reader& reader, const std::string& fileName);
