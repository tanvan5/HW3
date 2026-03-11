#include <iostream>
#include <string>
#include <fstream>
#include "../include/validation.h"
using std::string, std::size_t;

namespace validation {
    bool is_valid_password(string password){
        bool lenreq = false;
        bool upperreq = false;
        bool nonalnum = false;

        size_t length = password.size();
        if(length >= 8){
            lenreq = true;
        }
        for(char c : password){
            if(std::isupper(c)){
                upperreq = true;
            }
            if(!std::isalnum(c)){
                nonalnum = true;
            }
        }
        if(lenreq && upperreq && nonalnum){
            return true;
        }
        else{
            return false;
        }
    }
}
