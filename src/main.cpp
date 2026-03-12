#include <iostream>
#include <string>
#include <fstream>
#include "../include/audit_mode.h"
#include "../include/validation.h"

using std::string;

int main(int argc, char* argv[]) {
    if(argc==3){
        string input = argv[1];
        string output = argv[2];
        audit::process_file(input, output);
    }
    else{
        audit::run_menu();
    }
    return 0;
}