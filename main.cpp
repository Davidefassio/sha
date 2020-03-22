#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <fstream>

#include "sha.hpp"

void help();
void help_ansi();

int main(int argc, char* argv[]){
    bool flag = false;
    int sha_n, input_source, input_mode;
    std::string input, output;
    std::ifstream input_file;

    if(argc == 1){
        help();
        return 0;
    }
    else if(argc == 2){
    	if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0){
            help_ansi();
            return 0;
    	}
    }
    else if(argc == 4){
        if(argv[1][0] == '-'){
            sscanf(argv[1], "-%d", &sha_n);

            if(strcmp(argv[2], "-a") == 0 || strcmp(argv[2], "--ascii") == 0 || strcmp(argv[2], "-e") == 0 || strcmp(argv[2], "--hex") == 0 || strcmp(argv[2], "-b") == 0 || strcmp(argv[2], "--binary") == 0){
                if(strcmp(argv[3], "-s") == 0 || strcmp(argv[3], "--string") == 0){
                    flag = true;

                    if(strcmp(argv[2], "-a") == 0 || strcmp(argv[2], "--ascii") == 0){ input_mode = 0; }
                    else if(strcmp(argv[2], "-e") == 0 || strcmp(argv[2], "--hex") == 0) { input_mode = 1; }
                    else{ input_mode = 2; }
                }
            }
        }
    }
    else if(argc == 5){
        if(argv[1][0] == '-'){
            sscanf(argv[1], "-%d", &sha_n);

            if(strcmp(argv[2], "-a") == 0 || strcmp(argv[2], "--ascii") == 0 || strcmp(argv[2], "-e") == 0 || strcmp(argv[2], "--hex") == 0 || strcmp(argv[2], "-b") == 0 || strcmp(argv[2], "--binary") == 0){
                if(strcmp(argv[2], "-a") == 0 || strcmp(argv[2], "--ascii") == 0){ input_mode = 0; }
                else if(strcmp(argv[2], "-e") == 0 || strcmp(argv[2], "--hex") == 0) { input_mode = 1; }
                else{ input_mode = 2; }

                if(strcmp(argv[3], "-s") == 0 || strcmp(argv[3], "--string") == 0){
                    flag = true;
                    input_source = 0;
                    input.append(argv[4]);
                }
                else if(strcmp(argv[3], "-f") == 0 || strcmp(argv[3], "--file") == 0){
                    input_file.open(argv[4], std::ios::in);
                    if(!input_file.good()){
                        std::cout << "sha: An error occurred while opening the file" << std::endl;
                        return 0;
                    }

                    flag = true;
                    input_source = 1;
                }
            }
        }
    }

    if(!flag){  // Something wrong in the parameters
        std::cout << "sha: Error in the arguments." << std::endl;
        std::cout << "For some help digit: ./sha -h" << std::endl;
        return 0;
    }

    // Switch the sha algorithms
    switch(sha_n){
        case 1:{
            if(input_source == 0){
                output = sha_1(input, input_mode);
            }
            else if(input_source == 1){
                output = sha_1(input_file, input_mode);
            }
            break;
        }

        case 224:{
            if(input_source == 0){
                output = sha_224(input, input_mode);
            }
            else if(input_source == 1){
                output = sha_224(input_file, input_mode);
            }
            break;
        }

        case 256:{
            if(input_source == 0){
                output = sha_256(input, input_mode);
            }
            else if(input_source == 1){
                output = sha_256(input_file, input_mode);
            }
            break;
        }

        /* case 384:{
            if(input_source == 0){
                output = sha_384(input, input_mode);
            }
            else if(input_source == 1){
                output = sha_384(input_file, input_mode);
            }
            break;
        }

        case 512:{
            if(input_source == 0){
                output = sha_512(input, input_mode);
            }
            else if(input_source == 1){
                output = sha_512(input_file, input_mode);
            }
            break;
        }*/

        default:{
            std::cout << "sha: sha-" << sha_n << " doesn't exist" << std::endl;
            std::cout << "For some help digit: ./sha -h" << std::endl;
            return 0;
            break;
        }
    }

    std::cout << output << std::endl;

    // End
    return 0;
}

// Print out a brief guide of this program in plain text
void help(){
    std::cout << "NAME:\n";
    std::cout << "    sha - secure hash algorithm.\n\n";

    std::cout << "SYNOPSIS:\n";
    std::cout << "    ./sha {sha number} {Input format} {Input options} [Input specification]\n\n";

    std::cout << "SHA NUMBER:\n";
    std::cout << "Identify the algorithm that will process the input.\n";
    std::cout << "    -1   : use sha-1 algorithm, output's length = 160 bit;\n";
    std::cout << "    -224 : (sha-2 family) use sha-224 algorithm;\n";
    std::cout << "    -256 : (sha-2 family) use sha-256 algorithm;\n";
    std::cout << "    -384 : (sha-2 family) use sha-384 algorithm;\n";
    std::cout << "    -512 : (sha-2 family) use sha-512 algorithm.\n\n";

    std::cout << "INPUT FORMAT:\n";
    std::cout << "Specify the format of the input data.\n";
    std::cout << "    -a, --ascii\n";
    std::cout << "        the input character will be converted in ASCII code\n";
    std::cout << "        and the resulting bits will be processed.\n\n";
    std::cout << "    -e, --hex\n";
    std::cout << "        the input is a number written in hexadecimal.\n\n";
    std::cout << "    -b, --binary\n";
    std::cout << "        the input is a number written in binary.\n\n";

    std::cout << "INPUT OPTIONS:\n";
    std::cout << "Specify where the program will take the input.\n";
    std::cout << "    -s, --string\n";
    std::cout << "        take the string that follows as input.\n\n";
    std::cout << "    -f, --file\n";
    std::cout << "        take the contents of the specified file as input.\n";
    std::cout << "        The file may contain spaces and new lines.\n\n";

    std::cout << "INPUT SPECIFICATION:\n";
    std::cout << "A string without spaces, or between \"\", if the previous option is -s.\n";
    std::cout << "It can also be left blank after -s, the program will process the empty string.\n";
    std::cout << "A valid filename or path to a file which contain the input if the previous option is -f.\n\n";

    std::cout << "HELP:\n";
    std::cout << "    ./sha        --> view the help page in plain text.\n";
    std::cout << "    ./sha -h     --> view the help page using ANSI codes.\n";
    std::cout << "          --help\n\n";

    std::cout << "EXAMPLES:\n";
    std::cout << "    ./sha\n";
    std::cout << "    ./sha -h\n";
    std::cout << "    ./sha --help\n";
    std::cout << "    ./sha -1 -a -s\n";
    std::cout << "    ./sha -224 --hex -s ee78012aa4fbf45e0ba4e0147436a662\n";
    std::cout << "    ./sha -256 -a --string \"example with spaces\"\n";
    std::cout << "    ./sha -384 --ascii -f file_name_1.txt\n";
    std::cout << "    ./sha -512 -b --file /folder/binary_file.txt\n\n";

    std::cout << "COPYRIGHT:\n";
    std::cout << "    Copyright © 2020 Davide Fassio. MIT license.\n\n";
}

// Print out a brief guide of this program with ANSI escape codes
void help_ansi(){
    std::cout << "\e[4mNAME\e[0m\n";
    std::cout << "    sha - secure hash algorithm.\n\n";

    std::cout << "\e[4mSYNOPSIS\e[0m\n";
    std::cout << "    ./sha {\e[4msha number\e[0m} {\e[4mInput format\e[0m} {\e[4mInput options\e[0m} [\e[4mInput specification\e[0m]\n\n";

    std::cout << "\e[4mSHA NUMBER\e[0m\n";
    std::cout << "Identify the algorithm that will process the input.\n";
    std::cout << "    \e[1m-1\e[0m   : use sha-1 algorithm, output's length = 160 bit;\n";
    std::cout << "    \e[1m-224\e[0m : (sha-2 family) use sha-224 algorithm;\n";
    std::cout << "    \e[1m-256\e[0m : (sha-2 family) use sha-256 algorithm;\n";
    std::cout << "    \e[1m-384\e[0m : (sha-2 family) use sha-384 algorithm;\n";
    std::cout << "    \e[1m-512\e[0m : (sha-2 family) use sha-512 algorithm.\n\n";

    std::cout << "\e[4mINPUT FORMAT\e[0m\n";
    std::cout << "Specify the format of the input data.\n";
    std::cout << "    \e[1m-a, --ascii\e[0m\n";
    std::cout << "        the input character will be converted in ASCII code\n";
    std::cout << "        and the resulting bits will be processed.\n\n";
    std::cout << "    \e[1m-e, --hex\e[0m\n";
    std::cout << "        the input is a number written in hexadecimal.\n\n";
    std::cout << "    \e[1m-b, --binary\e[0m\n";
    std::cout << "        the input is a number written in binary.\n\n";

    std::cout << "\e[4mINPUT OPTIONS\e[0m\n";
    std::cout << "Specify where the program will take the input.\n";
    std::cout << "    \e[1m-s, --string\e[0m\n";
    std::cout << "        take the string that follows as input.\n\n";
    std::cout << "    \e[1m-f, --file\e[0m\n";
    std::cout << "        take the contents of the specified file as input.\n";
    std::cout << "        The file may contain spaces and new lines.\n\n";

    std::cout << "\e[4mINPUT SPECIFICATION\e[0m\n";
    std::cout << "A string without spaces, or between \"\", if the previous option is -s.\n";
    std::cout << "It can also be left blank after -s, the program will process the empty string.\n";
    std::cout << "A valid filename or path to a file which contain the input if the previous option is -f.\n\n";

    std::cout << "\e[4mHELP:\e[0m\n";
    std::cout << "    ./sha        --> view the help page in plain text.\n";
    std::cout << "    ./sha -h     --> view the help page using ANSI codes.\n";
    std::cout << "          --help\n\n";

    std::cout << "\e[4mEXAMPLES\e[0m\n";
    std::cout << "    ./sha\n";
    std::cout << "    ./sha -h\n";
    std::cout << "    ./sha --help\n";
    std::cout << "    ./sha -1 -a -s\n";
    std::cout << "    ./sha -224 --hex -s ee78012aa4fbf45e0ba4e0147436a662\n";
    std::cout << "    ./sha -256 -a --string \"example with spaces\"\n";
    std::cout << "    ./sha -384 --ascii -f file_name_1.txt\n";
    std::cout << "    ./sha -512 -b --file /folder/binary_file.txt\n\n";

    std::cout << "\e[4mCOPYRIGHT\e[0m\n";
    std::cout << "    Copyright © 2020 Davide Fassio. MIT license.\n\n";
}
