/******************************************************************
*      Equation parser utility Class V.0.1                       *
*                                                                *
*      Author: Iamthwee                                          *
*                                                                *
*      Filename: Equation.cpp                                    *
*                                                                *
*      Purpose: To provide easy functions for evaluating         *
*               mathematical expressions with multiple           *
*               nesting. Permittable operators:                  *
*               +*-/^()                                          *
*                                                                *
*                                                                *
*      Rights:  The proprietary rights are owned by me           *
*               alone.                                           *
*                                                                *
*               You may not take credit for writing              *
*               this, sell it, or remove this signature.         *
*                                                                *
*      Notes:   Two main methods exist:                          *
*               -set()                                           *
*               -rpn()                                           *
*               -An example is given for clarity.                *
*               -Error checks are incomplete                     *
*                                                                *
*                                                                *
******************************************************************/
#ifndef EQUATION_H_
#define EQUATION_H_

#include <iostream>
#include <string>
#include <sstream>
#include <stack>
#include <vector>
#include <cmath>

using namespace std;

class Equation
{
    //define public member functions
 public:
    Equation(); //default constructor
    ~Equation(); //default destructor

    string rpn(); //main method
    void set(const string & a); //main method

    double Eval(vector <string> & s);
    void Convert(const string & Infix, string & Postfix);
    bool TakesPrecedence(char OperatorA, char OperatorB);
    bool IsOperand(char ch);
    bool IsOperator(char ch);
    bool IsNumber(char ch);
    string ChangeMe(string a);
    string InsertSpace(string a);
    bool CheckValid(string a);
    string Next(string a);

    //define private member functions
 private:
    string Infix;
};

#endif
