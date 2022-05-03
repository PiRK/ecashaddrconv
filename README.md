# ecashaddrconv
Standalone C++ implementation of cashaddr extracted from Bitcoin ABC.

## Requirements
This library depends on OpenSSL for the sha256 operation required for computing legacy address checksums.

## Examples
You can find examples of how to use the API in the `example.cpp` file.

Run it with:
    
    g++ -o example cashaddr.cpp example.cpp  -lssl -lcrypto
    ./example


## Unit tests

To run unit tests, compile `tests.cpp` and run the resulting executable.
 
    g++ -o tests tests.cpp cashaddr.cpp -lssl -lcrypto
    ./tests

