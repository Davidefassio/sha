# SHA in C++

## Syntax
On Linux/Mac run the program using `./sha`, the examples below uses this syntax.\
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

## License
```
MIT License

Copyright (c) 2020 Davide Fassio

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Author
__Davide Fassio__

