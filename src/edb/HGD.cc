#include <assert.h>
#include "HGD.h"
#include <stdio.h>
#include "NTL/RR.h"

using namespace std;

/**
 * THIS IS A .C IMPLEMENTATION OF A FORTRAN IMPLEMENTATION WITH THE
 * SPECIFICATION GIVEN IN THE COMMENT BELOW.
 * I replaced some helper functions with more appropriate ones and adapted the
 * code to work with very large numbers such as ZZ and RR from NTL.
 */
/**       ALGORITHM 668, COLLECTED ALGORITHMS FROM ACM.
   C      THIS WORK PUBLISHED IN TRANSACTIONS ON MATHEMATICAL SOFTWARE,
   C      VOL. 14, NO. 4, PP. 397-398.
   C
   C     EXAMPLE DRIVER PROGRAM FOR ALGORITHM H2PEC
   C
   C     IIN       :  LOGICAL INPUT UNIT
   C     IOUT      :  LOGICAL OUTPUT UNIT
   C     NS        :  NUMBER OF RANDOM VARIATES TO BE GENERATED
   C     K, N1, N2 :  PARAMETERS OF THE HYPERGEOMETRIC DISTRIBUTION
   C     FK,FN1,FN2:  FLOATING POINT PARAMETER VALUES
   C     ISEED     :  RANDOM NUMBER SEED
   C     JX        :  HYPERGEOMETRIC RANDOM VARIATE GENERATED
   C     XMEAN     :  SAMPLE MEAN
   C     SVAR      :  SAMPLE VARIANCE
   C     TMEAN     :  TRUE MEAN
   C     TVAR      :  TRUE VARIANCE
   C     SUM       :  SUM OF HYPERGEOMETRIC RANDOM VARIATES JX
   C     SUM2      :  SUM OF SQUARE OF JX
   C
   C
   C     HYPERGEOMETRIC RANDOM VARIATE GENERATOR
   C
   C     METHOD
   C        IF (MODE - MAX(0,KK-NN2) .LT. 10), USE THE INVERSE CDF.
   C           OTHERWISE, USE ALGORITHM H2PE: ACCEPTANCE-REJECTION VIA
   C           THREE REGION COMPOSITION.  THE THREE REGIONS ARE A
   C           RECTANGLE, AND EXPONENTIAL LEFT AND RIGHT TAILS.
   C        H2PE  REFERS TO HYPERGEOMETRIC-2 POINTS-EXPONENTIAL TAILS.
   C        H2PEC REFERS TO H2PE AND "COMBINED."  THUS H2PE IS THE
   C           RESEARCH RESULT AND H2PEC IS THE IMPLEMENTATION OF A
   C           COMPLETE USABLE ALGORITHM.
   C
   C     REFERENCE
   C        VORATAS KACHITVICHYANUKUL AND BRUCE SCHMEISER,

   C        "COMPUTER GENERATION OF HYPERGEOMETRIC RANDOM VARIATES,"
   C        JOURNAL OF STATISTICAL COMPUTATION AND SIMULATION,
   C        22(1985), 2, 1985, 127-145.
   C
   C     REQUIRED SUBPROGRAMS
   C        AFC() : A DOUBLE-PRECISION FUNCTION TO EVALUATE
   C                   THE LOGARITHM OF THE FACTORIAL.
   C        RAND(): A UNIFORM (0,1) RANDOM NUMBER GENERATOR. -- since it is
      only once invoked for seed, I just return seed
   C
   C     ARGUMENTS
   C        NN1   : NUMBER OF WHITE BALLS          (INPUT)
   C        NN2   : NUMBER OF BLACK BALLS          (INPUT)
   C        KK    : NUMBER OF BALLS TO BE DRAWN    (INPUT)
   C        ISEED : RANDOM NUMBER SEED  (INPUT AND OUTPUT)
   C        JX    : NUMBER OF WHITE BALLS DRAWN   (OUTPUT)
   C
   C     STRUCTURAL VARIABLES
   C        REJECT: LOGICAL FLAG TO REJECT THE VARIATE GENERATE BY H2PE.
   C        SETUP1: LOGICAL FLAG TO SETUP FOR NEW VALUES OF NN1 OR NN2.
   C        SETUP2: LOGICAL FLAG TO SETUP FOR NEW VALUES OF KK.
   C        IX    : INTEGER CANDIDATE VALUE.
   C        M     : DISTRIBUTION MODE.
   C        MINJX : DISTRIBUTION LOWER BOUND.
   C        MAXJX : DISTRIBUTION UPPER BOUND.
   C        KS    : SAVED VALUE OF KK FROM THE LAST CALL TO H2PEC.
   C        N1S   : SAVED VALUE OF NN1 FROM THE LAST CALL TO H2PEC.
   C        N2S   : SAVED VALUE OF NN2 FROM THE LAST CALL TO H2PEC.
   C        K,N1,N2: ALTERNATE VARIABLES FOR KK, NN1, AND NN2
   C                   (ALWAYS (N1 .LE. N2) AND (K .LE. (N1+N2)/2)).
   C        TN    : TOTAL NUMBER OF WHITE AND BLACK BALLS
   C
   C     INVERSE-TRANSFORMATION VARIABLES
   C        CON   : NATURAL LOGARITHM  OF SCALE.
   C        P     : CURRENT SCALED PROBABILITY FOR THE INVERSE CDF.
   C        SCALE : A BIG CONSTANT (1.E25) USED TO SCALE THE
   C                   PROBABILITY TO AVOID NUMERICAL UNDERFLOW
   C        U     : THE UNIFORM VARIATE BETWEEN (0, 1.E25).
   C        W     : SCALED HYPERGEOMETRIC PROBABILITY OF MINJX.
   C
   C     H2PE VARIABLES
   C        S     : DISTRIBUTION STANDARD DEVIATION.
   C        D     : HALF THE AREA OF THE RECTANGLE.
   C        XL    : LEFT END OF THE RECTANGLE.
   C        XR    : RIGHT END OF THE RECTANGLE.
   C        A     : A SCALING CONSTANT.
   C        KL    : HIGHEST POINT OF THE LEFT-TAIL REGION.
   C        KR    : HIGHEST POINT OF THE RIGHT-TAIL REGION.
   C        LAMDL : RATE FOR THE LEFT EXPONENTIAL TAIL.
   C        LAMDR : RATE FOR THE RIGHT EXPONENTIAL TAIL.
   C        P1    : AREA OF THE RECTANGLE.
   C        P2    : AREA OF THE LEFT EXPONENTIAL TAIL PLUS P1.
   C        P3    : AREA OF THE RIGHT EXPONENTIAL TAIL PLUS P2.
   C        U     : A UNIFORM (0,P3) RANDOM VARIATE USED FIRST TO SELECT
   C                   ONE OF THE THREE REGIONS AND THEN CONDITIONALLY TO
   C                   GENERATE A VALUE FROM THE REGION.
   C        V     : U(0,1) RANDOM NUMBER USED TO GENERATE THE RANDOM
   C                   VALUE OR TO ACCEPT OR REJECT THE CANDIDATE VALUE.
   C        F     : THE HEIGHT OF THE SCALED DENSITY FUNCTION USED IN THE
   C                   ACCEPT/REJECT DECISION WHEN BOTH M AND IX ARE SMALL.
   C        I     : INDEX FOR EXPLICIT CALCULATION OF F FOR H2PE.
   C
   C   THE FOLLOWING VARIABLES ARE TEMPORARY VARIABLES USED IN
   C   COMPUTING THE UPPER AND LOWER BOUNDS OF THE NATURAL LOGARITHM
   C   OF THE SCALED DENSITY.  THE SECLEVEL::DETAILED DESCRIPTION IS GIVEN IN
   C   PROPOSITIONS 2 AND 3 OF THE APPENDIX IN THE REFERENCE.
   C              Y, Y1, YM, YN, YK, NK, R, S, T, E, G, DG, GU, GL, XM,
   C              XN, XK, NM
   C
   C        Y     : PRELIMINARY CONTINUOUS CANDIDATE VALUE, FLOAT(IX)
   C        UB    : UPPER BOUND FOR THE NATURAL LOGARITHM OF THE SCALED
   C                   DENSITY.
   C        ALV   : NATURAL LOGARITHM OF THE ACCEPT/REJECT VARIATE V.
   C        DR, DS, DT, DE: ONE OF MANY TERMS SUBTRACTED FROM THE UPPER
   C                   BOUND TO OBTAIN THE LOWER BOUND ON THE NATURAL
   C                   LOGARITHM OF THE SCALED DENSITY.
   C        DELTAU: A CONSTANT, THE VALUE 0.0034 IS OBTAINED BY SETTING
   C                   N1 = N2 = 200, K = 199, M = 100, AND Y = 50 IN
   C                   THE FUNCTION DELTA_U IN LEMMA 1 AND ROUNDING THE
   C                   VALUE TO FOUR DECIMAL PLACES.
   C        DELTAL: A CONSTANT, THE VALUE 0.0078 IS OBTAINED BY SETTING
   C                   N1 = N2 = 200, K = 199, M = 100, AND Y = 50 IN
   C                   THE FUNCTION DELTA_L IN LEMMA 1 AND ROUNDING THE
   C                   VALUE TO FOUR DECIMAL PLACES.
   C
 */

static RR
AFC(RR I)
{
/*      DOUBLE PRECISION FUNCTION AFC(I)
   C
   C     FUNCTION TO EVALUATE LOGARITHM OF THE FACTORIAL I
   C        IF (I .GT. 7), USE STIRLING'S APPROXIMATION
   C           OTHERWISE,  USE TABLE LOOKUP
 */
    double AL[8] =
    {0.0, 0.0, 0.6931471806, 1.791759469, 3.178053830, 4.787491743,
     6.579251212, 8.525161361};

    if (I <= 7) {
        return to_RR(AL[to_int(round(I))]);
    } else {
        RR LL = log(I);
        return (I+0.5) * LL - I + 0.399089934;
    }

};

// returns a random value between 0 and 1
// the seed keeps changing
static RR
randomValue(ZZ & seed, unsigned int seedLen)
{
    ZZ prBits = RandomBits_ZZ(2*seedLen);
    RR result = to_RR(prBits >> seedLen)/to_RR((to_ZZ(1) << seedLen));
    //if (DEBUG) {cerr << "rand bits are " << result << "\n";}
    return result;
}

ZZ
HGD(ZZ KK, ZZ NN1, ZZ NN2, ZZ SEED, unsigned int seedLen,
    unsigned int RRPrecision)
{
    SetSeed(SEED);
    RR::SetPrecision(RRPrecision);

    RR JX;   //the result
    RR TN, N1, N2, K;
    RR P, U, V, A, IX, XL, XR, M;
    RR KL, KR, LAMDL, LAMDR, NK, NM, P1, P2, P3;

    bool REJECT;
    RR MINJX, MAXJX;

    double CON = 57.56462733;
    double DELTAL = 0.0078;
    double DELTAU = 0.0034;
    double SCALE = 1.0e25;

    bool DEBUG = false;
/**
   C*****CHECK PARAMETER VALIDITY
 */

    if (  (NN1 <  0) ||
          (NN2 < 0) ||
          (KK < 0)  ||
          (KK > NN1 + NN2 )  ) {
        cerr << "invalid parameters NN1 " << NN1 << " NN2 " <<  NN2 <<
        " KK " << KK << "\n";
        assert(false);

    }
/**
   C*****IF NEW PARAMETER VALUES, INITIALIZE
 */
    REJECT = true;

    if (NN1 >= NN2)  {
        N1 = to_RR(NN2);
        N2 = to_RR(NN1);
    } else {
        N1 = to_RR(NN1);
        N2 = to_RR(NN2);
    }

    TN = N1 + N2;

    if (to_RR(KK + KK) >= TN)  {
        K  = TN - to_RR(KK);
    } else {
        K = to_RR(KK);
    }

    M  =  (K+1) * (N1+1) / to_RR(TN+2);

    if (DEBUG) {
        cerr << N1 << " : N1 \n";
        cerr << N2 << " : N2 \n";
        cerr << K << "  : K  \n";
        cerr << M << "  : M  \n";
    }

    if (K-N2 < 0) {
        MINJX = 0;
    } else {
        MINJX = K-N2;
    }

    if (N1 < K) {
        MAXJX = N1;
    } else {
        MAXJX = K;
    }

    if (DEBUG) {
        cerr << MINJX << " : MINJX \n";
        cerr << MAXJX << " : MAXJX \n";
    }
/**
   C*****GENERATE RANDOM VARIATE
 **/
    if (MINJX == MAXJX)  {
/*
   C        ...DEGENERATE DISTRIBUTION...
 */
        if (DEBUG) {
            cerr << "degenerate distribution \n";
            cerr << MAXJX << " : HGD \n";
        }
        return to_ZZ(MAXJX);

    } else if (M-MINJX < 10) {  //won't really happen in OPE cause M will be
                                // on the order of N1
/*
   C        ...INVERSE TRANSFORMATION...
 */
        RR W;
        if (K < N2) {
            W = exp(CON + AFC(N2) + AFC(N1+N2-K) - AFC(N2-K) - AFC(N1+N2));
        } else {
            W = exp(CON + AFC(N1) + AFC(K) - AFC(K-N2) - AFC(N1+N2));
        }

        bool flagTen = true;
        bool flagTwenty = true;
        int countFlagTen = 0, countFlagTwenty = 0;
/* 10 */
        while (flagTen) {
            countFlagTen++;
            if (countFlagTen % 500 == 0) {
                if (DEBUG) {
                    cerr << "passed through label ten " << countFlagTen <<
                    " times \n";
                }
            }
            flagTen = false;
            P  = W;
            IX = MINJX;
            U  = randomValue(SEED, seedLen) * SCALE;
            /* 20 */
            countFlagTwenty = 0;
            while (flagTwenty && !flagTen) {
                countFlagTwenty++;
                if (countFlagTwenty > 1000) {
                    assert(false);
                }
                flagTwenty = false;
                if (U > P)  {
                    U  = U - P;
                    P  = P * (N1-IX)*(K-IX);
                    IX = IX + 1;
                    P  = P / IX / (N2-K+IX);
                    if (IX > MAXJX) {
                        flagTen = true;
                    }
                    flagTwenty = true;
                }
            }
        }
    } else {
/**
   C        ...H2PE...
 */

        RR S;
        SqrRoot(S, (TN-K) * K * N1 * N2 / (TN-1) / TN /TN);
/**
   C           ...REMARK:  D IS DEFINED IN REFERENCE WITHOUT INT.
   C           THE TRUNCATION CENTERS THE CELL BOUNDARIES AT 0.5
 */

        RR D = trunc(1.5*S) + 0.5;
        XL = trunc(M - D + 0.5);
        XR = trunc(M + D + 0.5);
        A = AFC(M) + AFC(N1-M) + AFC(K-M) + AFC(N2-K+M);
        RR expon = A - AFC(XL) - AFC(N1-XL)- AFC(K-XL) - AFC(N2-K+XL);
        KL = exp(expon);
        KR = exp(A - AFC(XR-1) - AFC(N1-XR+1) - AFC(K-XR+1) - AFC(N2-K+XR-1));
        LAMDL = -log(XL * (N2-K+XL) / (N1-XL+1) / (K-XL+1));
        LAMDR = -log((N1-XR+1) * (K-XR+1) / XR / (N2-K+XR));
        P1 = 2*D;
        P2 = P1 + KL / LAMDL;
        P3 = P2 + KR / LAMDR;

        int countThirtyB = 0;
flagThirtyB:
        /* 30 */
        countThirtyB++;
        if (countThirtyB % 500 == 0) {
            if (DEBUG) {
                cerr << "count is " << countThirtyB << " \n";
            }
        }
        U = randomValue(SEED, seedLen) * P3;
        V = randomValue(SEED, seedLen);
        if (U < P1)  {
/*
   C           ...RECTANGULAR REGION...
 */
            IX    = XL + U;
        } else if  (U <= P2)  {
/*
   C           ...LEFT TAIL...
 */

            IX = XL + log(V)/LAMDL;
            if (IX < MINJX) {
                if (DEBUG) {cerr << "left. \n"; }
                goto flagThirtyB;
            }
            V = V * (U-P1) * LAMDL;
        } else  {
/*
   C           ...RIGHT TAIL...
 */
            IX = XR - log(V)/LAMDR;
            if (IX > MAXJX)  {
                if (DEBUG) {cerr << "right \n"; }
                goto flagThirtyB;
            }
            V = V * (U-P2) * LAMDR;
        }

/*
   C        ...ACCEPTANCE/REJECTION TEST...
 */

        RR F;
        if ((M < 100) || (IX <= 50))  {
/*
   C           ...EXPLICIT EVALUATION...
 */
            F = to_RR(1.0);
            if (M < IX) {

                for (RR I = M+1; I < IX; I++) {
                    /*40*/ F = F * (N1-I+1) * (K-I+1) / (N2-K+I) / I;
                }
            } else if (M > IX) {
                for (RR I = IX+1; I < M; I++) {
                    /*50*/ F = F * I * (N2-K+I) / (N1-I) / (K-I);
                }
            }
            if (V <= F)  {
                REJECT = false;
            }
        } else {
/*
   C        ...SQUEEZE USING UPPER AND LOWER BOUNDS...
 */

            RR Y   = IX;
            RR Y1  = Y + 1;
            RR YM  = Y - M;
            RR YN  = N1 - Y + 1;
            RR YK  = K - Y + 1;
            NK  = N2 - K + Y1;
            RR R   = -YM / Y1;
            RR S2  = YM / YN;
            RR T   = YM / YK;
            RR E   = -YM / NK;
            RR G   = YN * YK / (Y1*NK) - 1;
            RR DG  = to_RR(1.0);
            if (G < 0)  { DG = 1.0 +G; }
            RR GU  = G * (1+G*(-0.5+G/3.0));
            RR GL  = GU - 0.25 * sqr(sqr(G)) / DG;
            RR XM  = M + 0.5;
            RR XN  = N1 - M + 0.5;
            RR XK  = K - M + 0.5;
            NM  = N2 - K + XM;
            RR UB  = Y * GU - M * GL + DELTAU  + XM * R *
                     (1.+R*
                      (-.5+R/
                       3.))  + XN * S2 *
                     (1.+S2*
                      (-0.5+S2/
                       3.))  + XK * T *
                     (1.+T*(-.5+T/3.))   + NM * E * (1.+E*(-.5+E/3.));
/*
   C           ...TEST AGAINST UPPER BOUND...
 */

            RR ALV = log(V);
            if (ALV > UB) {
                REJECT = true;
            }
            else {
/*
   C              ...TEST AGAINST LOWER BOUND...
 */

                RR DR = XM * sqr(sqr(R));
                if (R < 0)  {
                    DR = DR / (1.+R);
                }
                RR DS = XN * sqr(sqr(S2));
                if (S2 < 0) {
                    DS = DS / (1+S2);
                }
                RR DT = XK * sqr(sqr(T));
                if (T < 0)  { DT = DT / (1+T); }
                RR DE = NM * sqr(sqr(E));
                if (E < 0)  {
                    DE = DE / (1+E);
                }
                if (ALV < UB-0.25*(DR+DS+DT+DE)  +(Y+M)*(GL-GU)-DELTAL) {
                    REJECT = false;
                } else {
/*
   C                 ...STIRLING'S FORMULA TO MACHINE ACCURACY...
 */

                    if (ALV <=
                        (A - AFC(IX) -
                         AFC(N1-IX)  - AFC(K-IX) - AFC(N2-K+IX)) ) {
                        REJECT = false;
                    } else {
                        REJECT = true;
                    }
                }
            }
        }
        if (REJECT)  {
            goto flagThirtyB;
        }
    }

/*
   C*****RETURN APPROPRIATE VARIATE
 */

    if (KK + KK >= to_ZZ(TN)) {
        if (NN1 > NN2) {
            IX = to_RR(KK - NN2) + IX;
        } else {
            IX =  to_RR(NN1) - IX;
        }
    } else {
        if (NN1 > NN2)  { IX = to_RR(KK) - IX; }
    }
    JX = IX;
    if (DEBUG) {cerr << JX << " : HGD \n"; }
    return to_ZZ(JX);
};

