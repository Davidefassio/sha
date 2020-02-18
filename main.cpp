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
    int sha_n;
    std::string input, output;

    std::cout << "Hash cfucntions: SHA by Davide Fassio" << std::endl << std::endl;

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
    else if(argc == 3){
        if(argv[1][0] == '-' && argv[2][0] == '-'){
            if(strcmp(argv[2], "-s") == 0){
                flag = true;
                sscanf(argv[1], "-%d", &sha_n);
            }
        }
    }
    else if(argc == 4){
        if(argv[1][0] == '-'){
            sscanf(argv[1], "-%d", &sha_n);

            if(strcmp(argv[2], "-s") == 0){
                flag = true;
                input.append(argv[3]);
            }
            else if(strcmp(argv[2], "-f") == 0){
                flag = true;

                std::ifstream in(argv[3], std::ios::in);
                if(!in.good()){
                    std::cout << "sha: An error occurred while opening the file" << std::endl;
                    return 0;
                }

                std::string line;
                int cnt = 0;
                while(!in.eof()){
                    in >> line;

                    if(line.length() > 0 && cnt > 0){
                        input.append(" ");
                        input.append(line);
                    }
                    else if(cnt == 0){
                        input.append(line);
                    }

                    line.clear();
                    cnt++;
                }
                in.close();
            }
        }
    }

    if(!flag){  // Something wrong in the parameters
        std::cout << "sha: Error in the arguments." << std::endl;
        std::cout << "For some help digit: ./sha -h" << std::endl;
        return 0;
    }

    // Switch the sha algs
    switch(sha_n){
        case 1:{
            output = sha_1(input);
            break;
        }

        /* case 224:{
            char output_224[225];
            sha_224(input, output_224);
            break;
        }

        case 256:{
            char output_256[257];
            sha_256(input, output_256);
            break;
        }

        case 384:{
            char output_384[385];
            sha_384(input, output_384);
            break;
        }

        case 512:{
            char output_512[513];
            sha_512(input, output_512);
            break;
        } */

        default:{
            std::cout << "sha: sha-" << sha_n << " doesn't exist" << std::endl;
            std::cout << "For some help digit: ./sha -h" << std::endl;
            return 0;
            break;
        }
    }

    std::cout << "sha-" << sha_n << " -> " << output << std::endl;

    // End
    return 0;
}

// Print out a brief guide of this program in plain text
void help(){
    std::cout << "NAME:\n";
    std::cout << "    sha - secure hash algorithm.\n\n";

    std::cout << "SYNOPSIS:\n";
    std::cout << "    ./sha [sha number] [Input options] {Input specification}\n\n";

    std::cout << "SHA NUMBER:\n";
    std::cout << "Identify the algorithm that will process the input.\n";
    std::cout << "    -1   : use sha-1 algorithm, output's length = 160 bit;\n";
    std::cout << "    -224 : (sha-2 family) use sha-224 algorithm;\n";
    std::cout << "    -256 : (sha-2 family) use sha-256 algorithm;\n";
    std::cout << "    -384 : (sha-2 family) use sha-384 algorithm;\n";
    std::cout << "    -512 : (sha-2 family) use sha-512 algorithm.\n\n";

    std::cout << "INPUT OPTIONS:\n";
    std::cout << "Specify where the program will take the input.\n";
    std::cout << "    -s : take the string that follow as input.\n";
    std::cout << "    -f : take the contents of the specified file as input.\n";
    std::cout << "         The file may contain spaces and new lines.\n\n";

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
    std::cout << "    ./sha -1 -s\n";
    std::cout << "    ./sha -224 -s example_string_without_spaces\n";
    std::cout << "    ./sha -256 -s \"example with spaces\"\n";
    std::cout << "    ./sha -384 -f file_name_1.txt\n";
    std::cout << "    ./sha -512 -f /folder/file_name_2.txt\n\n";

    std::cout << "COPYRIGHT:\n";
    std::cout << "    Copyright © 2020 Davide Fassio. MIT license.\n\n";
}

// Print out a brief guide of this program with ANSI escape codes
void help_ansi(){
    std::cout << "\e[4mNAME\e[0m\n";
    std::cout << "    sha - secure hash algorithm.\n\n";

    std::cout << "\e[4mSYNOPSIS\e[0m\n";
    std::cout << "    ./sha [\e[4msha number\e[0m] [\e[4mInput options\e[0m] {\e[4mInput specification\e[0m}\n\n";

    std::cout << "\e[4mSHA NUMBER\e[0m\n";
    std::cout << "Identify the algorithm that will process the input.\n";
    std::cout << "    -1   : use sha-1 algorithm, output's length = 160 bit;\n";
    std::cout << "    -224 : (sha-2 family) use sha-224 algorithm;\n";
    std::cout << "    -256 : (sha-2 family) use sha-256 algorithm;\n";
    std::cout << "    -384 : (sha-2 family) use sha-384 algorithm;\n";
    std::cout << "    -512 : (sha-2 family) use sha-512 algorithm.\n\n";

    std::cout << "\e[4mINPUT OPTIONS\e[0m\n";
    std::cout << "Specify where the program will take the input.\n";
    std::cout << "    -s : take the string that follow as input.\n";
    std::cout << "    -f : take the contents of the specified file as input.\n";
    std::cout << "         The file may contain spaces and new lines.\n\n";

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
    std::cout << "    ./sha -1 -s\n";
    std::cout << "    ./sha -224 -s example_string_without_spaces\n";
    std::cout << "    ./sha -256 -s \"example with spaces\"\n";
    std::cout << "    ./sha -384 -f file_name_1.txt\n";
    std::cout << "    ./sha -512 -f /folder/file_name_2.txt\n\n";

    std::cout << "\e[4mCOPYRIGHT\e[0m\n";
    std::cout << "    Copyright © 2020 Davide Fassio. MIT license.\n\n";
}
