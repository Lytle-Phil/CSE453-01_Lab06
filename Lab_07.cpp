#include <iostream>
#include <iomanip>
#include <string>
using namespace std;

void one(long number);
void two(long number);
void pass() { cout << "You pass :)\n"; }
void fail() { cout << "You've failed :(\n"; }
const char * passMessage = ":)";
const char * failMessage = ":(";

/**********************************************
 * MAIN : The top of the callstack.
 **********************************************/
int main()
{
   char text[8] = "*MAIN**";
   long number = 123456;
   void (*pointerFunction)() = fail;
   const char * message = failMessage;

   // display the initial values of the local variables
   cout << "main() : " << (void *)main << endl;
   cout << "\ttext:             " << text              << endl;
   cout << "\tnumber:           " << number            << endl;
   cout << "\tmessage:          " << message           << endl;
   cout << "\tfunction pointer: ";
   pointerFunction();

   // call the other functions
   one(number + 111111);     // 234567

   // display the new values of the local variables
   cout << "main() - after\n";
   cout << "\ttext:             " << text              << endl;
   cout << "\tnumber:           " << number            << endl;
   cout << "\tmessage:          " << message           << endl;
   cout << "\tfunction pointer: ";
   pointerFunction();

   return 0;
}

/************************************************
 * CONVERT TO STRING
 * Convert the data from p into a human-readable string
 * by removing all the unprintable characters and replacing
 * them with a dot
 ***********************************************/
string displayCharArray(const char * p)
{
   string output;
   for (int i = 0; i < 8; i++)
       output += string(" ") + (p[i] >= ' ' && p[i] <= 'z' ? p[i] : '.');
   return output;
}

/**********************************************
 * ONE : The next item on the call stack
 **********************************************/
void one(long number)               // 234567
{
   char text[8] = "**ONE**";

   cout << "one() : " << (void *)one << endl;
   cout << "\tmessage: " << (void *)failMessage << endl;
   cout << "\tfail():  " << (void *)fail        << endl;
   cout << "\tpass():  " << (void *)pass        << endl;

   two(number + 111111);    // 345678
}

/**********************************************
 * TWO : The bottom of the call stack
 **********************************************/
void two(long number)              // 345678
{
   // start your display of the stack from this point
   long bow = number + 111111;     // 456789
   char text[8] = "**TWO**";
   long * pLong = &bow;
   char * pChar = text;

   // header for our table. Use these setw() offsets in your table
   cout << '[' << setw(2) << 'i' << ']'
        << setw(15) << "address"
        << setw(25) << "hexadecimal"
        << setw(30) << "decimal"
        << setw(18) << "characters"
        << endl;
   cout << "----+"
        << "---------------+"
        << "------------------------+"
        << "-----------------------------+"
        << "-----------------+\n";
   for (long i = 32; i >= -4; i--)   // You may need to change 24 to another number
   {
      //the local variable bow is to be used as index 0
      ////////////////////////////////////////////////
      // Insert code here to display the callstack
          cout << "[" << setw(2) << i << "]"
           << setw(15) << &(*(pLong + (i)))  //0x61fe88
           << setw(25) << hex << *(pLong + (i)) 
           << setw(30) << dec << *(pLong + (i))
           << setw(18) << displayCharArray(pChar + ((i+1)* 8))
           << endl;

     //  cout << *(pLong + i) << endl;
      //
      ////////////////////////////////////////////////
   }

   ////////////////////////////////////////////////
   // Insert code here to change the variables in main()
   
   for(long i = 128; i >= -8; i--)
   {
      // change text in main() to "*main**"
      if(displayCharArray(pChar + i) == " * M A I N * * .")
      {
         *(pChar + i + 1) = 'm';
         *(pChar + i + 2) = 'a';
         *(pChar + i + 3) = 'i';
         *(pChar + i + 4) = 'n';
               
      }

      // change number in main() to 654321
      if(*(pLong + i) == 123456)
      {
         *(pLong + i) = 654321;        
      }
      
      // change pointerFunction in main() to point to pass      
      if (*(pLong + i) == (long)(void *)fail)
      {
         *(pLong + i) = (long)(void *)pass;
      } 
      
      // change message in main() to point to passMessage      
      if (*(pLong + i) == (long)(void*)failMessage)
      {
         *(pLong + i) = (long)(void*)passMessage;
      } 
      
   }

   //
   ////////////////////////////////////////////////
   return;
}
