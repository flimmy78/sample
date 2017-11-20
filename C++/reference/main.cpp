int main()
{
    // 非const 引用
    int val = 42;
    int &ref = val;
    //int &refi = 42;  //错误，非const引用只能绑定到对象

    double val2 = 3.14;

    const int &ref2 = val2; //const引用， 绑定到对象, 类型转换
    (void) ref2;

    const int &ref3 = val2 * 3; //const引用, 绑定到表达式，类型转换
    (void) ref3;

    const int &ref4 = 314; //const引用, 绑定到字面值
    (void) ref4;

    return ref;
}
