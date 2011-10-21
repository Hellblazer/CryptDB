#include <string>
#include <NTL/ZZ.h>

inline std::string
StringFromZZ(const NTL::ZZ &x)
{
    std::string s;
    s.resize(NumBytes(x), 0);
    NTL::BytesFromZZ((uint8_t*) &s[0], x, s.length());
    return s;
}

inline NTL::ZZ
ZZFromString(const std::string &s)
{
    return NTL::ZZFromBytes((const uint8_t *) s.data(), s.length());
}
