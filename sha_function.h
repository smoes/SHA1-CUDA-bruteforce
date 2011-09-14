#include <stdio.h>
#include <stdlib.h>
#include <cutil_inline.h>



using namespace std;


#define uc  unsigned char


void start(unsigned int *, int, unsigned char *);
__global__ void smash(int, unsigned char *, unsigned int *);
__device__ void sha(unsigned char *, int); 
__device__ void memInit(unsigned int *, unsigned char*, int);



