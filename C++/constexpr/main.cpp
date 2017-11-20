constexpr int Dec(int i)
{ return i-1; }  

int main()
{
    constexpr int i = 0;

    constexpr int val = i * 2;

    const int val1 = Dec (3); //有效

    int a = 3;
    const int val2 = Dec (a); //有效

    const int j = 0;

    const  int k = j * 2;

}
