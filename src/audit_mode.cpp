#include <iostream>
#include <string>
#include <fstream>
#include "../include/audit_mode.h"
#include "../include/validation.h"

using std::string, std::cout, std::cin, std::endl, std::size_t;

namespace audit {
    void process_file(string input, string output){
        char delim;
        char delim_output;
        if(input.size() > 4){
            if(input.find(".tsv") == std::string::npos){
                delim = '\t';
            }
            if(input.find(".csv") == std::string::npos){
                delim = ',';
            }
        }
        if(output.size() > 4){
            if(output.find(".tsv") == std::string::npos){
                delim_output = '\t';
            }
            if(output.find(".csv") == std::string::npos){
                delim_output = ',';
            }
        }

        std::ifstream infile(input);
        std::ofstream outfile(output, std::ios::app);

        if (!infile.is_open()){
            std::cerr << "infile error;";
        }
        if (!outfile.is_open()){
            std::cerr << "outfile error";
        }

        string username, email, password;

        while(std::getline(infile, username, delim) && std::getline(infile, email, delim) && std::getline(infile, password)){
            if(!validation::is_valid_password(password)){
                outfile << username << delim_output << email << delim_output << password << '\n';
            }
        }

        infile.close();
        outfile.close();
        

    }
    void run_menu(){
        bool loop = true;
        while(loop){
            string stringchoice;
            int choice;
            cout << "1. Check a single password" << endl;
            cout << "2. Process a TSV/CSV file" << endl;
            cout << "3. Quit" << endl;
            cin >> stringchoice;
            choice = std::stoi(stringchoice);
            switch(choice){
                case 1: {
                    string password;
                    cout << "Enter a single password" << endl;
                    cin >> password;
                    if(validation::is_valid_password(password)){
                        cout << "Valid" << endl;
                    }
                    else{
                        cout << "Invalid" << endl;
                    }
                    break;
                }
                case 2: {
                    string input;
                    string output;
                    cout << "Enter the desired input file" << endl;
                    cin >> input;

                    cout << "Enter the desired output file" << endl;
                    cin >> output;

                    process_file(input, output);
                    break;

                }
                case 3: {
                    loop = false;
                    break;
                }
                default: {
                    break;
                }
            }
        }
    }
}