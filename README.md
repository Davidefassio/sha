# SHA in C++

## Syntax
On Linux/Max run the program using `./sha`, the examples below uses this syntax.\
On Windows run it using `sha.exe`.

For some help: 
```c++
./sha -h
      --help
```

Ordinary syntax:
```c++
./sha -1    -a        -s        "string or filename"
      -224  --ascii   --string
      -256  -e        -f
      -384  --hex     --file
      -512  -b
            --binary
```

Some examples:
```c++
      ./sha
      ./sha -h
      ./sha --help
      ./sha -1 -a -s
      ./sha -224 --hex -s ee78012aa4fbf45e0ba4e0147436a662
      ./sha -256 -a --string "example with spaces"
      ./sha -384 --ascii -f file_name_1.txt
      ./sha -512 -b --file /folder/binary_file.txt
```
