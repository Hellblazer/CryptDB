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
*               *+-/^()                                          *
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
*      Modifications made by Catherine Redfield                  *
*      (cat_red@mit.edu) for integration into CryptDB            *
*      July 1, 2011.                                             *
*                                                                *
******************************************************************/

#include "Equation.h"

//Polynomial constructor
Equation::Equation()
{
    Infix = "";
}

//Polynomial destructor.
Equation::~Equation()
{
    //do its work
}

//Setter method
void
Equation::set(const string & a)
{
    Infix = a;
}

bool
Equation::IsOperand(char ch)
{
    if (
        ((ch >= '0') && (ch <= '9'))||
        (ch == 'v') ||
        (ch == 'y') ||
        (ch == '.')
        )
        return true;
    else
        return false;
}

bool
Equation::IsNumber(char ch)
{
    if (
        ((ch >= '0') && (ch <= '9'))||
        (ch == '.')
        )
        return true;
    else
        return false;
}

bool
Equation::IsOperator(char ch)
{
    if ((ch == '+') ||
        (ch == '-') ||
        (ch == '*') ||
        (ch == '/') ||
        (ch == '^'))
        return true;
    else
        return false;
}

bool
Equation::TakesPrecedence(char OperatorA, char OperatorB)
{
    if (OperatorA == '(')
        return false;
    else if (OperatorB == '(')
        return false;
    else if (OperatorB == ')')
        return true;
    else if ((OperatorA == '^') && (OperatorB == '^'))
        return false;
    else if (OperatorA == '^')
        return true;
    else if (OperatorB == '^')
        return false;
    else if ((OperatorA == '*') || (OperatorA == '/'))
        return true;
    else if ((OperatorB == '*') || (OperatorB == '/'))
        return false;
    else
        return true;
}

void
Equation::Convert(const string & Infix, string & Postfix)
{
    stack <char> OperatorStack;
    char TopSymbol, Symbol;
    unsigned int k;

    for (k = 0; k < Infix.size(); k++)
    {
        Symbol = Infix[k];
        if (IsOperand(Symbol))
            Postfix = Postfix + Symbol;
        else
        {
            while ((!OperatorStack.empty()) &&
                   (TakesPrecedence(OperatorStack.top(), Symbol)))
            {
                TopSymbol = OperatorStack.top();
                OperatorStack.pop();
                Postfix = Postfix + TopSymbol;
            }
            if ((!OperatorStack.empty()) && (Symbol == ')'))
                OperatorStack.pop();  // discard matching (
            else
                OperatorStack.push(Symbol);
        }
    }

    while (!OperatorStack.empty())
    {
        TopSymbol = OperatorStack.top();
        OperatorStack.pop();
        Postfix = Postfix + TopSymbol;
    }
}

string
Equation::ChangeMe(string tmp)
{
    for(unsigned int i = 0; i <tmp.length(); i++)
    {
        if(IsNumber(tmp[i])==true)
        {
            if(IsNumber(tmp[i+1])==false)
            {
                tmp.insert(i+1, "v");
            }
        }
    }
    // -ve * -ve case
    for (unsigned int i = 0; i < tmp.length(); i++)
    {
        if(tmp[i]=='-')
        {
            if((tmp[i-1]!='v')&&(tmp[i-1]!=')'))
            {
                tmp.replace(i,1,"y");
            }
        }
    }
    return tmp;
}

string
Equation::InsertSpace(string tmp)
{
    for(unsigned int i = 0; i < tmp.length(); i++)
    {
        if (IsOperator(tmp[i])==true)
        {
            tmp.insert(i+1, " ");
            //Insert a space after all
            //found operators
        }
        else if( tmp[i]=='v' )
        {
            tmp.replace(i,1," ");
            //replace the v with a space
            //for clarity
        }
    }

    for (unsigned int i = 0; i < tmp.length(); i++)
    {
        if(tmp[i]=='y')
        {
            tmp.replace(i,1,"-");
        }
    }
    return tmp;
}

bool
Equation::CheckValid(string tmp)
{
    //incomplete
    //Changed check that consecutive '+', '-'
    //signs do not exist
    for (unsigned int i = 0; i < tmp.length(); i++)
    {
        if((tmp[i]=='+')||(tmp[i]=='-'))
        {
            if((tmp[i+1]=='+')||(tmp[i+1]=='-'))
            {
                return false;
            }
        }
    }

    string array = "0123456789+-*/^().";

    unsigned int count = 0;
    for (unsigned int i = 0; i < tmp.length(); i++)
    {
        for(unsigned int j = 0; j < array.length(); j++)
        {
            if(tmp[i]==array[j])
            {
                count++;
            }
        }
    }

    if (count == tmp.length())
    {
        return true;
    }
    else
    {
        return false;
    }

}

string
Equation::Next(string tmp)
{
    vector <string> array;

    int spaces = 0;
    for (unsigned int a = 0; a < tmp.length(); a++ )
    {
        if(tmp[a]==' ')
        {
            spaces++;
        }
    }
    string token;
    istringstream iss(tmp);
    while ( getline(iss, token, ' ') )
    {
        array.push_back(token);
    }

    stack <string> my_stack; //initialise stack
    vector <string> temp;
    string ch;

    for (int i = 0; i < spaces; i++)
    {
        string s;
        s = array[i]; //make it easier to read

        if ((s!="+")&&(s!="*")&&(s!="-")&&(s!="^")&&(s!="/"))
        {
            my_stack.push(s);
            //push numbers onto the stack
        }
        else //i.e if it encounters an operator
        {
            my_stack.push(s); //push operator onto stack

            for ( int i = 0; i < 3; i++ )
            {
                temp.push_back(my_stack.top());
                my_stack.pop(); //erase from the stack
            }

            double z;
            z = Eval(temp);
            ostringstream outs;
            outs << z; // Convert value into a string.
            ch = outs.str();

            my_stack.push(ch);
            temp.clear();
        }
    }
    //cout << ch;
    return ch;
}

double
Equation::Eval(vector <string> & temp)
{

    string a,b,c;
    a = temp[2]; b = temp[0]; c = temp[1];
    double x,y,z;
    istringstream ins,inse;
    ins.str(a); inse.str(c);
    ins >> x;
    inse >> y;

    if (b == "+")
    {
        z = x + y;
        return z;
    }
    else if (b == "-")
    {
        z = x - y;
        return z;
    }
    else if (b == "*")
    {
        z = x * y;
        return z;
    }
    else if (b == "/")
    {
        z = x / y;
        return z;
    }
    else if (b == "^")
    {
        z = pow(x,y);
        return z;
    }
    return -1;
}

string
Equation::rpn()
{
    string Postfix;
    string hold;
    string res;
    if(CheckValid(Infix)==true)
    {
        bool isnum = true;
        for (unsigned int i = 0; i < Infix.size(); i++) {
            if (!IsNumber(Infix[i])) {
                isnum = false;
                break;
            }
        }
        if (isnum) {
            return Infix;
        }

        string temp;
        temp = ChangeMe(Infix);

        Convert(temp, Postfix);

        //cerr << "****Postfix****\n" << endl
        //   << InsertSpace(Postfix);

        hold = InsertSpace(Postfix);

        //cerr << "\n\n****Solution****\n\n";
        res = Next(hold);
        //cerr << "\n\n";
    }
    else
    {
        //cout << "Expression invalid retard!\n";
        cerr << "ERROR: Equation does not make sense" << endl;
        res = "";
    }
    return res;
}

/*int main()
   {
   //test cases
   Equation a,b,c;

   a.set("3-(5-(7+1))^2*(-5)+13");
   a.rpn();

   b.set("3.2+(6.34*(1.7))");
   b.rpn();

   c.set("3+4*2/(1-5)^2");
   c.rpn();

   cin.get();
   return 0;

   }*/
