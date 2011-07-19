#include "log.h"

uint64_t logger::enable_mask = (1ULL << log_debug) | (1ULL << log_warn);

