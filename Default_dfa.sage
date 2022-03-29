#In our code we have considered the last two rounds of the DEFAULT cipher (no key scheduling algorithm)
#with no permutation involved in the last round. Since there are Sbox grouping in the permutation, we have 
#considered here the first four nibble of the state from the left and recovered the possible options for the
#corresponding 16 bits of the secret key.


import random

from itertools import product 

#************************************Function Definitions Start*****************************************
#SBox of the DEFAULT LAYER
def Sbox(x0,x1,x2,x3):
    y0 =  x0 + x1 + x2
    y1 =  x0*x1 + x0*x2 + x0 + x1*x3 + x1 + x2*x3
    y2 =  x1 + x2 + x3
    y3 =  x0*x1 + x0*x2 + x1*x3 + x2*x3 + x2 + x3
    return([y0%2,y1%2,y2%2,y3%2])

#inverse of the SBox of the DEFAULT LAYER
def Sbox_in(x0,x1,x2,x3):
    y0 =  x1 + x2 + x3
    y1 = x0*x1 + x0*x3 + x0 + x1*x2 + x2*x3 + x3
    y2 = x0*x1 + x0*x3 + x1*x2 + x1 + x2*x3 + x2
    y3 = x0 + x1 + x3
    return([y0%2,y1%2,y2%2,y3%2])

# Second last round of the DEFAULT LAYER
def second_last_round(S,K):
    #subcells operation
    i = 0
    while(i < 128):
        S_sb = Sbox(S[i],S[i+1],S[i+2],S[i+3])
        S[i:i+4] = S_sb[:4]
        i = i+4
    
    #permbits operation
    S_new = [0]*128
    for i in range(128):
        S_new[Perm[i]] = S[i] 

    #addroundkey operation  
    for i in range(128):
        S[i] = (S_new[i]+K[i])%2
        S_new[i] = S[i]
    return S_new

# Last round of the DEFAULT LAYER
def last_round(S,K):
    #subcells operation
    i = 0
    while(i < 128):
        S_sb = Sbox(S[i],S[i+1],S[i+2],S[i+3])
        S[i:i+4] = S_sb[:4]
        i = i+4
    #addroundkey operation  
    for i in range(128):
        S[i] = (S[i]+K[i])%2
        
    return S

#Inverse of second last round of the DEFAULT LAYER
def second_last_round_in(S,K):
    #addroundkey operation  
    for i in range(128):
        S[i] = (S[i]+K[i])%2
        
    #inverse permbits operation
    S_new = [0]*128
    for i in range(128):
        S_new[Perm_in[i]] = S[i] 
        
    #inverse subcells operation 
    i = 0
    while(i < 128):
        S_sb = Sbox_in(S_new[i],S_new[i+1],S_new[i+2],S_new[i+3])
        S_new[i:i+4] = S_sb[:4]
        i = i+4
    return S_new

#Inverse of last round of the DEFAULT LAYER     
def last_round_in(S,K):
    #addroundkey operation  
    for i in range(128):
        S[i] = (S[i]+K[i])%2
    
    #inverse subcells operation 
    i = 0
    while(i < 128):
        S_sb = Sbox_in(S[i],S[i+1],S[i+2],S[i+3])
        S[i:i+4] = S_sb[:4]
        i = i+4
 
    return S

#******************************************Function Definitions End**************************************

#permutation
Perm = [0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3, 4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7, 8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11, 12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15, 16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19, 20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23, 24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27, 28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31]

#inverse permutation
Perm_in = [0]*128
for i in range(128):
    Perm_in[Perm[i]] = i

#original key
K_org = [random.randint(0,1) for i in range(128)]

#original state
S_org = [random.randint(0,1) for i in range(128)]

#initial state
S = [0]*128
S = S_org[:128]

#***************************************Last Round Analysis**********************************************    
#In this part we recover the 256 possible keys of the 16 bits part of the key from the last round 
#by analysing each of the 4 Sboxes separately corresponding to the nibble position(pos) depending on the
#index(line125). By changing the index one can recover the other parts of the key. 

#state after the second last round
S_slr = second_last_round(S,K_org)

#storing the positions where the bits of the indexed nibble get permuted to after the permbits operation
index = 0
pos = Perm[16*index:16*index+4]

#set to store the possible key candidates
K_op = []

for l in range(4):
    #set to store keys
    Key = []
    
    #nibble corresponding to the pos[l]-th bit
    Nib = floor(pos[l]/4)
    
    #set to store faults in binary
    F = []
    
    #set to store faulty nibble
    C_faulty = []
    
    #set to store nibble without fault
    C_org = []
    
    #analysis for each of the faults
    for j in range(3):
        
        #initial state for the last round
        S[:128] = S_slr[:128]
            
        #changing faults in binary
        if(j > 0):
            j_bin = ZZ(j).digits(base = 2, padto = 4)
            
            #adding the fault to the corresponding nibble
            for i in range(4):
                S[4*Nib+i] = (S[4*Nib+i]+j_bin[i])%2
        
            #storing faults in binary
            F.append(j_bin)
        
        S=last_round(S,K_org)    
        #storing state without injecting fault
        if(j == 0):
            C_org = C_org + S[4*Nib : 4*Nib+4]
            
        #storing faulty state
        if(j > 0):
            C_faulty.append(S[4*Nib : 4*Nib+4])
            
    
    i = 0
    
    #possible key options at a nibble
    K = []
    
    #fault analysis at the last round
    for i in range(2):
        
        #possible key options for each fault
        B = []
        for k in range(16):
            k_bin = ZZ(k).digits(base = 2, padto = 4)
            
            a = [(C_org[j]+k_bin[j])%2 for j in range(4)]
            a = Sbox_in(a[0], a[1], a[2], a[3])
            
            b = [(C_faulty[i][j]+k_bin[j])%2 for j in range(4)]
            b = Sbox_in(b[0], b[1], b[2], b[3])
            
            diff = [(a[j]+b[j])%2 for j in range(4)]
            
            if(diff == F[i]):
                B.append(k)
        K.append(B)
    
    #intersection of the possible key options corresponding to each fault
    for i in range(1,2):
        K[0] = Set(K[0]).intersection(Set(K[i]))
        
    #storing the key candidates from the intersection in binary
    for i in range(len(K[0])):
        k = K[0][i]
        k_bin = ZZ(k).digits(base = 2, padto = 4)
        Key.append(k_bin)
    K_op.append(Key)


K_option = []

#Original keybits at the sixteen positions corresponding to the 1st nibble of penultimate round
U = []
for l in range(4):
    nib = floor(pos[l]/4)
    for i in range(4):
        U.append(K_org[4*nib+i])
print('Original keybits at the sixteen positions corresponding to the 1st nibble of penultimate round=', U)

#options after last round fault for 16 bits of the key
for i1, i2, i3, i4 in product(range(len(K_op[0])), range(len(K_op[1])),\
                              range(len(K_op[2])), range(len(K_op[3]))):
    temp = []
    temp = temp + K_op[0][i1][:4] + K_op[1][i2][:4] + K_op[2][i3][:4] + K_op[3][i4][:4]
    K_option.append(temp)

print('Number of options after last round fault for 16 bits of key is', len(K_option))

#***************************************Last Two Round Analysis*********************************************
#From the above last round analysis we get 256 possible key options of the 16 bits part of the key.
#We have stored that possible options of the 16 bits part of the key in the array K_option.
#In this part we have filtered this 256 possible options by inducing nibble base fault at the state at the 
#begining of the second last round. In the following, 'for loop in l' indicates the nibble position 4*l+16*aa,  
#(aa depends on floor(pos[0]/4)) where we induce the fault. 


aa = floor(pos[0]/4)
for l in range(4):
    F = []
    C_org = []
    C_faulty = []
    for j in range(3):
        
        S[:128] = S_org[:128]
        if(j > 0):
            j_bin = ZZ(j).digits(base = 2, padto = 4) #converting fault into binary
            
            #adding the fault to the corresponding nibble
            for i in range(4):
                S[i+4*l+16*aa] = (S[i+4*l+16*aa]+j_bin[i])%2
            F.append(j_bin) #Storing the induced fault
            
        
            
        S=second_last_round(S,K_org)    
        S=last_round(S,K_org)   
        #storing the original state    
        if(j == 0):
            for i in range(128):
                C_org.append(S[i])
    
        #storing the faulty states  
        if(j > 0):
            L = []
            for i in range(128):
                L.append(S[i])
            C_faulty.append(L)
    
    A = []
    for l1 in range(4):
        for i1 in range(4):
            A.append(Perm[i1+4*l1+16*aa])
    A.sort() #Set of key bit positions that have to be recovered 
    KK = [0]*128
    K_OPTION_NEW = []
    for op in range(len(K_option)):
        for i in range(16):
            KK[A[i]] = K_option[op][i]
        match = 0
        for j in range(2):
            a=[0]*128
            b=[0]*128
            a[:] = C_org[:128]
            b[:] = C_faulty[j][:128]            
            a =last_round_in(a,KK)
            b =last_round_in(b,KK)
                        
            c = [0]*128
            d = [0]*128
            c = second_last_round_in(a,KK)
            d = second_last_round_in(b,KK)
            a[:128] = c[:128]
            b[:128] = d[:128]
            temp = 4*l+16*aa
            diff = [(a[temp]+b[temp])%2,(a[temp+1]+b[temp+1])%2,\
                    (a[temp+2]+b[temp+2])%2, (a[temp+3]+b[temp+3])%2]
            if(diff == F[j]):
                match = match+1
        
        if(match == 2):
            K_OPTION_NEW.append(K_option[op])
    print('Number of options for the key:',len(K_OPTION_NEW),  )
    
    K_option = []
    for i in range(len(K_OPTION_NEW)):
        K_option.append(K_OPTION_NEW[i])

Key_nib = [floor(pos[0]/4),floor(pos[1]/4),floor(pos[2]/4),floor(pos[3]/4)]
print('Rcovered nibble positions of the key:',Key_nib)
for i in range(len(K_option)):
    if(K_option[i] == U):
        print('We have a match!', K_option[i])

