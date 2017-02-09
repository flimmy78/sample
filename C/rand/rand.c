/* 模拟srand(),rand()函数的实现, 使用线性同余算法求随机数 */
#include <stdio.h>  
#include <time.h>  
static unsigned long rand_seed;  
void mysrand (unsigned long int);  
void myrand ();  
int  
main (void)  
{  
    int i;  
  
    mysrand (time (NULL));  
    for (i = 0; i < 100; i++)  
      {  
          myrand ();  
      }  
printf ("\n");
    return 0;  
}  
  
void  
mysrand (unsigned long seed)  
{  
    rand_seed = seed;  
}  
  
void  
myrand ()  
{  
    /* 这些常量是编译器的设置，每个编译器常量不一样 */
    rand_seed = (rand_seed * 16807L) % ((1 << 31) - 1);  
    printf ("%ld ", rand_seed);  
}  
