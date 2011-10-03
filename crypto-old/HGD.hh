#include <NTL/ZZ.h>


/*
 * KK is the number of elements drawn from an urn where there are NN1 white
 * balls, NN2 black balls and ISEED is some randomness;
 * The result is the number of white balls in the KK sample.
 * RANDNR must be a uniform number between 0 and 1 (high precision)
 *
 * The implementation is based on an adaptation of the H2PEC alg for large
 * numbers, see HGD.c for details
 */
NTL::ZZ HGD(NTL::ZZ KK, NTL::ZZ NN1, NTL::ZZ NN2, NTL::ZZ SEED, unsigned int seedLen,
            unsigned int RRPrecision);
