#include <sys/stat.h>
#include <stdio.h>

off_t get_file_size (char* path)
{
    long long filesize = 0;
    struct stat statbuff;  
    if(stat(path, &statbuff) < 0)
    {  
        printf ("stat failed\n");
        return filesize;  
    }
    else
    {  
        filesize = statbuff.st_size;  
    }  
    return filesize;  
}
int main(int argc, char* argv[] )
{
    long long  filesize = get_file_size (argv[1]);
    printf ("filesize:%lld\n", filesize);

    return 0;
}
