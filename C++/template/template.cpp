#include <iostream>
#include <iomanip>
#include "template.h"

using namespace std;

template<class T> 
A<T>::A(){}

template<class T> 
T A<T>::g(T a,T b){
    return a+b;
}

template <class T> double swap(T& a, T& b)
{
    T c = b;
    b = a;
    a = c;
}

/* 声明的时候需要加template 这一段 */
template<class T1, class T2, class T3> 
class B {
    public: 
        T1 a; 
        T2 b; 
        T3 hy(T1 c, T2 d);
};

/* 定义的时候同样需要加template 这一段, 明确告诉编译器这个是模板 */
template<class T1, class T2, class T3> 
T3 B<T1,T2,T3>::hy(T1 c, T2 d)
{
    return (c+d);
}

int main(){
    A<int> a;
    cout<<a.g(2,3.2)<<endl;

    A<double> b;
    cout<<b.g(2,3.2)<<endl;

    int s1 = 5;
    int s2 = 10;
    ::swap (s1, s2);

    cout<<"s1 "<<s1<<","<<"s2 "<<s2<<endl;

    B<int, double, double> c;
    cout << c.hy(1,2.1) << endl;

    B<int, int, int> d;
    cout << d.hy(1, 2.1) << endl;
}
