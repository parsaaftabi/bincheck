#pragma once

#include "reader.h"
#include "report.h"

Report parsePe(const Reader& reader, const std::string& fileName);
