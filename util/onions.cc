#include "util/onions.hh"
#include "util/util.hh"

SECLEVEL
getMin(onion o) {
    switch (o) {
    case oDET: {return SECLEVEL::PLAIN_DET;}
    case oOPE: {return SECLEVEL::PLAIN_OPE;}
    case oAGG: {return SECLEVEL::PLAIN_AGG;}
    case oSWP: {return SECLEVEL::PLAIN_SWP;}
    default: {}
    }
    assert_s(false, "invalid onion");
    return SECLEVEL::INVALID;
    
}


SECLEVEL
getMax(onion o) {
    switch (o) {
    case oDET: {return SECLEVEL::SEMANTIC_DET;}
    case oOPE: {return SECLEVEL::SEMANTIC_OPE;}
    case oAGG: {return SECLEVEL::SEMANTIC_AGG;}
    case oSWP: {return SECLEVEL::SWP;}
    default: {}
    }

    assert_s(false, "invalid onion");
    return SECLEVEL::INVALID;
}
