#include <stdio.h>


int main()
{
    FILE *fp = fopen ("file.txt", "rb");
    if (NULL == fp)
    {
        return 0;
    }

    char buf[16] = {0};
    int readlen = fread (buf, 1, 1, fp);
    if (readlen <= 0)
    {
        return 0;
    }

    int len = ftell (fp);
    printf ("len1:%d\n", len);
    int oldlen = len;

    fseek (fp, 0L, SEEK_END);

    len = ftell (fp);

    printf ("len:%d\n", len);

    fseek (fp, oldlen, SEEK_SET);
    len = ftell (fp);

    printf ("len:%d\n", len);
    

    return 0;
}
