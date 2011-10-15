#pragma once

#include <string>

typedef enum fieldType {
    TYPE_TEXT,
    TYPE_INTEGER,
    TYPE_AGG_RESULT_COUNT,
    TYPE_AGG_RESULT_SUM,
    TYPE_AGG_RESULT_SET,
    TYPE_OPE,
} fieldType;

typedef enum onion {
    oDET,
    oOPE,
    oAGG,
    oNONE,
    oSWP,
    oINVALID,
} onion;

#define SECLEVELS(m)    \
    m(INVALID)          \
    m(PLAIN)            \
    m(PLAIN_DET)        \
    m(DETJOIN)          \
    m(DET)              \
    m(SEMANTIC_DET)     \
    m(PLAIN_OPE)        \
    m(OPEJOIN)          \
    m(OPE)              \
    m(SEMANTIC_OPE)     \
    m(PLAIN_AGG)        \
    m(SEMANTIC_AGG)     \
    m(PLAIN_SWP)        \
    m(SWP)              \
    m(SEMANTIC_VAL)     \
    m(SECLEVEL_LAST)

typedef enum class SECLEVEL {
#define __temp_m(n) n,
SECLEVELS(__temp_m)
#undef __temp_m
} SECLEVEL;

const std::string levelnames[] = {
#define __temp_m(n) #n,
SECLEVELS(__temp_m)
#undef __temp_m
};

inline SECLEVEL string_to_sec_level(const std::string &s)
{
#define __temp_m(n) if (s == #n) return SECLEVEL::n;
SECLEVELS(__temp_m)
#undef __temp_m
    // TODO: possibly raise an exception
    return SECLEVEL::INVALID;
}

//returns max and min levels on onion o
SECLEVEL getMax(onion o);
SECLEVEL getMin(onion o);
