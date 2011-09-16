#include "sha_function.h"
#include <time.h>
#define word unsigned int 

/* f1 to f4 */

__device__ inline word f1( word x, word y, word z) { return ( ( x & y ) | ( ~x & z ) ); }
__device__ inline word f2( word x, word y, word z) { return ( x ^ y ^ z ); }
__device__ inline word f3( word x, word y, word z) { return ( ( x & y ) | ( x & z ) | ( y & z ) ); }
__device__ inline word f4( word x, word y, word z) { return ( x ^ y ^ z ); } 

/* SHA init values */

__constant__ word I1 = 0x67452301L;
__constant__ word I2 = 0xEFCDAB89L;
__constant__ word I3 = 0x98BADCFEL;
__constant__ word I4 = 0x10325476L;
__constant__ word I5 = 0xC3D2E1F0L;

/* SHA constants */

__constant__ word C1 = 0x5A827999L;
__constant__ word C2 = 0x6Ed9EBA1L;
__constant__ word C3 = 0x8F1BBCDCL;
__constant__ word C4 = 0xCA62C1D6L;

/* 32-bit rotate */

__device__ inline word ROT(word x,int n){ return ( ( x << n ) | ( x >> ( 32 - n ) ) ); }

/* main function */

#define CALC(n,i) temp =  ROT ( A , 5 ) + f##n( B , C, D ) +  W[i] + E + C##n  ; E = D; D = C; C = ROT ( B , 30 ); B = A; A = temp


__shared__ word * hash;

int main()
{
    char input[40], tmp[8]; 
    unsigned char * res;
    word hash[5];
    double time_tmp, time;

    // Init output and scan input

    printf("------------------------------------------------\n");
    printf("Welcome to a SHA-brute force programm using cuda\n");
    printf("------------------------------------------------\n\n");
    printf("Please enter your hash value: \t");

    
    scanf("%s", input);

    for(int i = 0; i < 5; i++)
    {
        for(int j = 0; j < 8; j++)
            tmp[j] = input[i * 8 + j];

        hash[i]=strtol(tmp,NULL,16);
    }
    
    printf("input verification: \t\t");
    for(int i = 0; i < 5; i++)
        printf("%X", hash[i]);

    printf("\n\n\n");

    res = (uc *) malloc(80);
    for(int i = 0; i < 10; i++)
        res[i] = 0;


    // Start calculation

    time = 0;   

    clock_t test = clock();
        
    printf("Checking for every possible 1-6 character password. \n\n");
   

    for(int i = 1; i < 7; i++)
    {
        printf("Execution started for string length %d\n.", i);
	// Function call
        start(hash, i, res);
        time_tmp = ( (double)clock() - test ) / CLOCKS_PER_SEC;
        time += time_tmp;
        printf("Finished. Time needed: %f\n", time_tmp);
        printf("Result: %s\n\n", (res[0] == 0 ? "No result found." : res));
	// If res != 0 (hash found) stop
	if(res[0] != 0) break;
        for(int j = 0; j < 10; j++)
            res[j] = 0;
    }
    // res still 0, no result
    if(res[0] == 0)
	printf("Unfortunately no valid hash was found :( \n Check your input character range. But maybe the password is too long?\n");
    else
	printf("Total execution time: %f \n", time);

    return 1;
}

void start(word * hash_tmp,  int length, unsigned char * res)
{
    unsigned char * buffer = 0;
    unsigned char * buffer_fill[10];
    cutilSafeCall ( cudaMalloc((void** ) &buffer, 10 * sizeof(unsigned char)) );
    cutilSafeCall ( cudaMalloc((void** ) &hash, 5 * sizeof(word)) );
    

    for(int i = 0; i <10; i++)
        buffer_fill[i] = 0x0; 
    
    cudaMemcpy (hash, hash_tmp, 5 * sizeof(word), cudaMemcpyHostToDevice);
    cudaMemcpy (buffer, buffer_fill, 10 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    
    // Call actual brute force kernel-function with 
    // - blocks: count of possible chars squared
    // - threads: possible chars
   
    smash<<<9025,95>>>(length, buffer, hash);

    cudaMemcpy(res, buffer, 10 * sizeof(unsigned char), cudaMemcpyDeviceToHost);
    //cudaMemcpy(debug, hash, 5 * sizeof(word), cudaMemcpyDeviceToHost);

    cudaError_t err = cudaGetLastError();
    if( cudaSuccess != err) 
        printf( "Cuda error: %s.\n",  cudaGetErrorString( err) );


    cudaFree(buffer);
    cudaFree(hash);
}


/*
 * kernel-function __global__ void smash(int, char, in)
 *
 * Initialize with count of possible chars squared as the block-num
 * and count of possible chars as the thread-num
 * With cx (where cx is char at position x of the tested word) the 
 * first 3 chars are set like:
 * 
 *   - c0: thread-num
 *   - c1: block-num / 95
 *   - c2: block-num % 95
 *
 * That guarantees every possible unique combination of the first
 * the chars.
 *
 * input:
 *   - length: length of the words 
 *   - buffer: buffer to write-back result, return value
 *   - hash: hash that needs to be decrypted
 *
*/

__global__ void smash(int length, unsigned char * buffer, word * hash)
{
    word h0,h1,h2,h3,h4;
    int higher = 126;
    int lower = 32;
    unsigned char input_cpy[10];
    int carry = 1;

    // load into register
    h0 = hash[0];
    h1 = hash[1];
    h2 = hash[2];
    h3 = hash[3];
    h4 = hash[4];

    if(length > 3)
       for(int i = 3; i < 10; i++)
           input_cpy[i] = lower;

    // init input_cpy
    input_cpy[0] = threadIdx.x + lower;
    if(length > 1)
		input_cpy[1] = (blockIdx.x / 95) + lower;
	if(length > 2)
	    input_cpy[2] = (blockIdx.x % 95) + lower;

    // Length for carry flag (break) if length < 3
    short int s = length < 3 ? length : 3;

    // value @length as a flag.
    // if != 0 break
    for(short int i = length; i < 10; i++)
            input_cpy[i] = 0;

    // Init words for SHA
    word W[80],A,B,C,D,E,temp;
 
    // calculate all possible charsets with the
    // given threadId, blockId and length
    while(input_cpy[length] == 0 && buffer[0] == 0) //@TODO || flag) 
    {
        // Calculate sha for given input.
        // DO THE SHA ------------------------------------------------------

        memInit(W, input_cpy, length);
        for(int i = 16; i < 80; i++)
            W[i] = ROT( ( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16] ) , 1 ); 

        A = I1;    B = I2;    C = I3;    D = I4;    E = I5;

        CALC(1,0);  CALC(1,1);  CALC(1,2);  CALC(1,3);  CALC(1,4);
        CALC(1,5);  CALC(1,6);  CALC(1,7);  CALC(1,8);  CALC(1,9);
        CALC(1,10); CALC(1,11); CALC(1,12); CALC(1,13); CALC(1,14);
        CALC(1,15); CALC(1,16); CALC(1,17); CALC(1,18); CALC(1,19);
        CALC(2,20); CALC(2,21); CALC(2,22); CALC(2,23); CALC(2,24);
        CALC(2,25); CALC(2,26); CALC(2,27); CALC(2,28); CALC(2,29);
        CALC(2,30); CALC(2,31); CALC(2,32); CALC(2,33); CALC(2,34);
        CALC(2,35); CALC(2,36); CALC(2,37); CALC(2,38); CALC(2,39);
        CALC(3,40); CALC(3,41); CALC(3,42); CALC(3,43); CALC(3,44);
        CALC(3,45); CALC(3,46); CALC(3,47); CALC(3,48); CALC(3,49);
        CALC(3,50); CALC(3,51); CALC(3,52); CALC(3,53); CALC(3,54);
        CALC(3,55); CALC(3,56); CALC(3,57); CALC(3,58); CALC(3,59);
        CALC(4,60); CALC(4,61); CALC(4,62); CALC(4,63); CALC(4,64);
        CALC(4,65); CALC(4,66); CALC(4,67); CALC(4,68); CALC(4,69);
        CALC(4,70); CALC(4,71); CALC(4,72); CALC(4,73); CALC(4,74);
        CALC(4,75); CALC(4,76); CALC(4,77); CALC(4,78); CALC(4,79);
    
        // That needs to be done, == with like (A + I1) =0 hash[0] 
        // is wrong all the time?!
        word tmp1, tmp2, tmp3, tmp4, tmp5;   
 
        tmp1 = A + I1;
        tmp2 = B + I2;
        tmp3 = C + I3;
        tmp4 = D + I4;
        tmp5 = E + I5;

        // if result was found, cpy to buffer
        if( tmp1 == h0 && 
            tmp2 == h1 &&
            tmp3 == h2 &&
            tmp4 == h3 &&
            tmp5 == h4 )
        { 
            buffer[0] = input_cpy[0];   
            buffer[1] = input_cpy[1];   
            buffer[2] = input_cpy[2];   
            buffer[3] = input_cpy[3];   
            buffer[4] = input_cpy[4];   
            buffer[5] = input_cpy[5];   
            buffer[6] = input_cpy[6];   
            buffer[7] = input_cpy[7];   
            buffer[8] = input_cpy[8];   
            buffer[9] = input_cpy[9];   
            
            break;
        }
        
        // adding new value
        // DO THE ADDITION ----------------------------------------------
    
        for(int i = s; i < 10; i++)
        {
            if(carry)
            {
                input_cpy[i] = input_cpy[i]+ 1;
                if(input_cpy[i] > higher)
                {
                    input_cpy[i] = lower;
                    carry = 1;
                } else 
                    carry = 0;
            } else 
                break;
        }

        carry = 1;

    }

}


/*
 * device function __device__ void memInit(uint, uchar, int)
 * 
 * Prepare word for sha-1 (expand, add length etc)
*/


__device__ void memInit(word * tmp, unsigned char input[], int length)
{

    int stop = 0;
    // reseting tmp
    for(int i = 0; i < 80; i++) tmp[i] = 0;

    // fill tmp like: message char c0,c1,c2,...,cn,10000000,00...000
    for(int i = 0; i < length; i+=4)
    {
        for(int j = 0; j < 4; j++)
            if(i + j < length)
                tmp[i/4] |= input[i+j] << (24-j * 8);
            else 
            {
                stop = 1;
                break;
            }
        if(stop)
            break;
    }
    tmp[length/4] |= 0x80 << (24-(length%4) * 8);     // Append 1 then zeros
    // Adding length as last value
    tmp[15] |= length * 8;
}
