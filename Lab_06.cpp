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
       // See if any dangerous characters has been encountered. 
       // Mitigates comment, tautology, and additional statement attacks
        if (password[i] == '\'' || password[i] == ';' || password[i] == '-' || password[i] == ' ')
            return false;

        // mitigate union attack
        if (i < password.length() - 5) {
           if ((password[i] == 'U' || password[i] == 'u') &&
              (password[i+1] == 'N' || password[i+1] == 'n') && 
              (password[i+2] == 'I' || password[i+2] == 'i') && 
              (password[i+3] == 'O' || password[i+3] == 'o') && 
              (password[i+4] == 'N' || password[i+4] == 'n'))
              return false;
        }
    }

    // Loop through the username strings to search for problem charater
    for (int i = 0; i < username.length(); i++){
        // See if any dangerous characters has been encountered. 
        // Mitigates comment, tautology, and additional statement attacks
        if (username[i] == '\'' || username[i] == ';' || username[i] == '-' || username[i] == ' '))
            return false;

        // mitigate union query attack
        if (i < username.length() - 5) {
           if ((username[i] == 'U' || username[i] == 'u') &&
              (username[i + 1] == 'N' || username[i + 1] == 'n') &&
              (username[i + 2] == 'I' || username[i + 2] == 'i') &&
              (username[i + 3] == 'O' || username[i + 3] == 'o') &&
              (username[i + 4] == 'N' || username[i + 4] == 'n'))
              return false;
        }
    }
    return true;
}

int main(){
    
    // TEST CASE 1
    string usernameTestNoAttack = "John";
    string passwordTestNoAttack = "password";
    cout << endl
         << "TEST CASE 01" << endl
		 << "------------" << endl
		 << "Type of attack: None" << endl
         << "Mitigation: Weak" << endl
         << "Expected Result: There is no attack so there should be no attack detected." 
         <<endl << endl;
        if(weakMitigation(usernameTestNoAttack, passwordTestNoAttack))
            generateSQLStatement(usernameTestNoAttack, passwordTestNoAttack);
        else
            cout << "Attack detected" << endl;
    // END OF TEST CASE 1

    // TEST CASE 2
    cout << endl
         << "TEST CASE 02" << endl
		 << "------------" << endl
		 << "Type of attack: None" << endl
         << "Mitigation: Strong" << endl
         << "Expected Result: There is no attack so there should be no attack detected." 
         <<endl << endl;
        if(strongMitigation(usernameTestNoAttack, passwordTestNoAttack))
            generateSQLStatement(usernameTestNoAttack, passwordTestNoAttack);
        else
            cout << "Attack detected" << endl;
    // END OF TEST CASE 2
    
    // TEST CASE 3
    string usernameTestTuatologAttack = "John";
    string passwordTestTuatologyAttack = "na' OR 'x' = 'x";
    cout << endl
         << "TEST CASE 03" << endl
		 << "------------" << endl
		 << "Type of attack: Tautology" << endl
         << "Mitigation: Weak" << endl
         << "Expected Result: The system will detect the attack." <<endl << endl;
    if(weakMitigation(usernameTestTuatologAttack,passwordTestTuatologyAttack))
        generateSQLStatement(usernameTestTuatologAttack, passwordTestTuatologyAttack);
    else
        cout << "Attack detected" << endl;
    // END OF TEST CASE 3
   
    // TEST CASE 4
    cout << endl
         << "TEST CASE 04" << endl
		 << "------------" << endl
		 << "Type of attack: Tautology" << endl
         << "Mitigation: Strong" << endl
         << "Expected Result: The system will detect the attack." <<endl << endl;
    if(strongMitigation(usernameTestTuatologAttack,passwordTestTuatologyAttack))
        generateSQLStatement(usernameTestTuatologAttack, passwordTestTuatologyAttack);
    else
        cout << "Attack detected" << endl;
    // END OF TEST CASE 4

    // TEST CASE 5
    string usernameTestAdditionalStatementAttack = "Bob";
    string passwordTestAdditionalStatementAttack = "na'; INSERT INTO passwordList (name, passwd) VALUES 'Adam', '1234";
    cout << endl
         << "TEST CASE 05" << endl
		 << "------------" << endl
		 << "Type of attack: Additional Statement" << endl
         << "Mitigation: Weak" << endl
         << "Expected Result: The system will detect the attack." <<endl << endl;
    if(weakMitigation(usernameTestAdditionalStatementAttack,passwordTestAdditionalStatementAttack))
        generateSQLStatement(usernameTestAdditionalStatementAttack, passwordTestAdditionalStatementAttack);
    else
        cout << "Attack detected" << endl;
    // END OF TEST CASE 5

    // TEST CASE 6
    cout << endl
         << "TEST CASE 06" << endl
		 << "------------" << endl
		 << "Type of attack: Additional Statement" << endl
         << "Mitigation: Strong" << endl
         << "Expected Result: The system will detect the attack." <<endl << endl;
    if(strongMitigation(usernameTestAdditionalStatementAttack,passwordTestAdditionalStatementAttack))
        generateSQLStatement(usernameTestAdditionalStatementAttack, passwordTestAdditionalStatementAttack);
    else
        cout << "Attack detected" << endl;
    // END OF TEST CASE 6


    strongMitigation("1","2");
    return 0;
}