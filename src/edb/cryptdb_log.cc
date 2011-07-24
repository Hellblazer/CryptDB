#include "cryptdb_log.h"

uint64_t cryptdb_logger::enable_mask = (1ULL << log_debug) | (1ULL << log_warn);

