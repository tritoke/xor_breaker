# xor_breaker
A haskell program for breaking the XOR cipher where a key is repeated until it is as long as the plaintext, then the ascii values of both are XOR'd together to get the cipher text. Uses the method described in https://cryptopals.com/sets/1/challenges/6.

## Compilation
run ```ghc --make -O2 xor_breaker``` to compile the program.
