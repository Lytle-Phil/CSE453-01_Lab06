using namespace std;
#include<iostream>
#include<string>

/*  Function: Generate SQL Statement
*   Description: Receives two strings as parameters and creates a fake
*                SQL statement which is output to the console.
*/
void generateSQLStatement(string userName, string password){
    cout << "SELECT * FROM users WHERE username = '" << userName << "' and password = '" << password << "';" << endl ;
    return;
}

/*  Function: Strong Mitigation
*   Description: Receives two strings as parameters. Comapares these strings
*                to a white list to prevent SQL injection attacks.
*/
bool strongMitigation(string userName, string password){
    bool isValidUsername = false;
    bool isValidPassword = false;
    const int size = 4;
    // The whitelist for the representation of the "database"
    string whiteListUsername[size] = {"John", "Bob", "Joe", "Bill"};
    string whiteListPassword[size] = {"password","1234","colorado113","123@4!a"};

    // Compare the username and password to the white list.
    for(int i = 0; i < size ; i++){
        if(userName == whiteListUsername[i]){
            isValidUsername = true;
        }
        if(password == whiteListPassword[i]){
            isValidPassword = true;
        }
    }

    return isValidUsername && isValidPassword;
}

/*  Function: Weak Mitigation
*   Description: Receives two strings as parameters and loops through them
*                removing any symbols used in a SQL injection attack.
*/
bool weakMitigation(string username, string password){
    
    // Loop through the password strings to search for problem charater
    for (int i = 0; i < password.length(); i++){
        // See if a ' has been encountered.
        if (password[i] == '\'')
            return false;
    }

    // Loop through the username strings to search for problem charater
    for (int i = 0; i < username.length(); i++){
        // See if a ' has been encountered.
        if (username[i] == '\'')
            return false;
    }
    return true;
}

int main(){
    
    // TEST CASE 1
    string usernameTest01 = "JohnDoe";
    string passwordTest01 = "na' OR 'x' = 'x";
    cout << endl
         << "TEST CASE 01" << endl
		 << "------------" << endl
		 << "Type of attack: Tautology" << endl
         << "Mitigation: None" << endl
         << "Expected Result: The system will not detect the attack." <<endl << endl;
        generateSQLStatement(usernameTest01, passwordTest01);
    // END OF TEST CASE 1

    // TEST CASE 2
    string usernameTest02 = "JohnDoe";
    string passwordTest02 = "na' OR 'x' = 'x";
    cout << endl
         << "TEST CASE 02" << endl
		 << "------------" << endl
		 << "Type of attack: Tautology" << endl
         << "Mitigation: Weak" << endl
         << "Expected Result: The system will detect the attack." <<endl << endl;
    if(weakMitigation(usernameTest02,passwordTest02))
        generateSQLStatement(usernameTest02, passwordTest02);
    else
        cout << "Attack detected" << endl;
    // END OF TEST CASE 1
   


    strongMitigation("1","2");
    return 0;
}