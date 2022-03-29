# DIFFERENTIAL FAULT ATTACK

This repository contains the source code for the paper, **Differential Fault Attack on DEFAULT**.


## Repository Structure

`Default_dfa.sage`-In this code we have considered the last two rounds of DEFAULT LAYER (no key scheduling algorithm) and have not included the permutation operation in the last round. By
fixing the index (`line 125 in the script`) among {0,1,...,7} one can recover the possible key options for the corresponding 4 key nibbles i.e., 16 bits of the key. Changing the index value one by one 
 and storing the possible options one recover the possible options for the whole secret key by fixing the original key. Original key and the state at the begining of the second last round are taken as random in this code.
 1. We have recovered 256 possible options for 16 bits part of the key from the last round analysis.
 2. Next we have filtered the key space from 256 to 4 by inducing fault in the state before the begining of the second last round and also verify the original key is present in the reduced key
    space.


## Software Used

1. [SageMath 9.2](https://www.sagemath.org/download.html) 


## How to Run
Compile through terminal using `sage <filename>`
