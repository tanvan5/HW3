#ifndef AUDIT
#define AUDIT

#include <iostream>
#include <string>
using std::string;

namespace audit {
    void process_file(string input, string output);
    void run_menu();
}


#endif