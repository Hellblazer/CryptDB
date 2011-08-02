#include "cryptdb_log.h"

uint64_t cryptdb_logger::enable_mask =
    cryptdb_logger::mask(log_group::log_debug) |
    cryptdb_logger::mask(log_group::log_warn);

