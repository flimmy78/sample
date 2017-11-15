/* https://www.cnblogs.com/hughdong/p/6910044.html */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define OK 1
#define ERROR 0
#define TRUE 1
#define FALSE 0
#define OVERFLOW -2
typedef int Status;
/* 存储结构 */
#define blank '#'
#define CHUNKSIZE 4 //块大小
typedef struct Chunk
{
    char ch[CHUNKSIZE];
    struct Chunk *next;
} Chunk;
typedef struct
{
    Chunk *head, *rear; //串的头和尾指针
    int curlen; //串的当前长度
} LString;
/* 函数列表 */
void InitString(LString *T);
Status StrAssign(LString *T, char *chars);
Status StrCopy(LString *T, LString S);
Status StrEmpty(LString S);
int StrCompare(LString S, LString T);
int StrLength(LString S);
Status ClearString(LString *S);
Status Concat(LString *T, LString S1, LString S2);
Status SubString(LString *Sub, LString S, int pos, int len);
int Index(LString S, LString T, int pos);
void Zip(LString *S); //压缩串
Status StrInsert(LString *S, int pos, LString T);
Status StrDelete(LString *S, int pos, int len);
Status Replace(LString *S, LString T, LString V);
void StrPrint(LString T);
void DestroyString();
/* 主函数 */
int main()
{
    int pos, len, flag;
    char *s1 = "Hello,LString!", *s2 = "Booooo!",  *s3 = "123#4", *s4 = "Hello,LString!!", *s5 = "Insert!", *s6 = "Insert!!", *s7 = "***", *s8 = "o"; //此种赋值方式,最后一个字符结束后,下一个字符位为空,可以通过*s1==NULL判断字符串结束
    LString t1, t2, t3, t4, t5, t6;
    InitString(&t1); //初始化t1
    InitString(&t2); //初始化t2
    printf("--------------------------\n");
    printf("StrEmpty...OK.\n");
    if(StrEmpty(t1))
        printf("t1 is Empty\n");
    else
        printf("t1 is not Empty\n");
    printf("StrLength...OK.\n");
    printf("length:%d\n", StrLength(t1));
    printf("--------------------------\n");
    printf("StrAssign...OK.\n");
    StrAssign(&t1, s1);
    printf("t1:");
    StrPrint(t1);
    printf("length:%d\n", StrLength(t1));
    StrAssign(&t2, s2);
    printf("t2:");
    StrPrint(t2);
    printf("length:%d\n", StrLength(t2));
    printf("--------------------------\n");
    printf("StrCopy...OK.\n");
    StrCopy(&t3, t1);
    printf("t3:");
    StrPrint(t3);
    printf("--------------------------\n");
    InitString(&t4);
    StrAssign(&t4, s4);
    flag = StrCompare(t1, t4);
    printf("StrCompare...OK.\n");
    StrPrint(t1);
    if (flag == 0)
        printf("==\n");
    else if(flag > 0)
        printf(">\n");
    else if(flag < 0)
        printf("<\n");
    StrPrint(t4);
    printf("--------------------------\n");
    printf("ClearString...OK.\n");
    ClearString(&t3);
    if(StrEmpty(t3))
        printf("t3 is Empty\n");
    else
        printf("t3 is not Empty\n");
    printf("--------------------------\n");
    printf("Concat...OK.\n");
    InitString(&t5);
    Concat(&t5, t1, t2);
    printf("t5:");
    StrPrint(t5);
    printf("length:%d\n", StrLength(t5));
    printf("--------------------------\n");
    printf("StrInsert Insert! ...OK.\n");
    StrAssign(&t3, s5);
    StrInsert(&t5, 21, t3);
    StrPrint(t5);
    printf("length:%d\n", StrLength(t5));
    printf("--------------------------\n");
    printf("StrDelete pos:13 len:5 ...OK.\n");
    StrDelete(&t5, 13, 5);
    StrPrint(t5);
    printf("length:%d\n", StrLength(t5));
    printf("--------------------------\n");
    printf("SubString He ...OK.\n");
    SubString(&t6, t5, 1, 2);
    printf("length:%d\n", StrLength(t6));
    printf("--------------------------\n");
    printf("Index Insert!! ...OK.\n");
    StrPrint(t5);
    ClearString(&t3);
    StrAssign(&t3, s6);
    printf("index pos:%d\n", Index(t5, t3, 1));
    printf("--------------------------\n");
    printf("Replace o -> *** ...OK.\n");
    ClearString(&t3);
    StrAssign(&t3, s7);
    ClearString(&t2);
    StrAssign(&t2, s8);
    Replace(&t5, t2, t3);
    StrPrint(t5);
    printf("--------------------------\n");
    return OK;
}
/* 初始化空串,不分配空间 */
void InitString(LString *T)
{
    T->head = NULL;
    T->rear = NULL;
    T->curlen = 0;
}
Status StrAssign(LString *T, char *chars)
{
    int len, blockNum, i, j;
    Chunk *p, *q;
    len = strlen(chars);
    if (!len || strchr(chars, blank)) //长度为0或包含#时结束
        return ERROR;
    T->curlen = len;
    blockNum = len / CHUNKSIZE; //计算结点数
    if (len % CHUNKSIZE)
        ++blockNum;
    for (i = 0; i < blockNum; ++i) //循环生成新节点
    {
        p = (Chunk *)malloc(sizeof(Chunk));
        if (!p)
            exit(OVERFLOW);
        if (T->head == NULL) //如果是第一个节点
            T->head = q = p;
        else
        {
            q->next = p;
            q = p;
        }
        for (j = 0; j < CHUNKSIZE && *chars; ++j) //每次新增一个块链即赋值,chars指针随之++,当chars指向空字符时结束
        {
            *(q->ch + j) = *chars;
            ++chars;
        }
        if (!*chars) //当*chars指向空字符(最后一个链块时)
        {
            T->rear = p;
            T->rear->next = NULL;
            for (; j < CHUNKSIZE; ++j) //当chars结束时j的值直接在此处使用
                *(q->ch + j) = blank;
        }
    }
    return OK;
}
Status StrCopy(LString *T, LString S)
{
    //另一个思路:将S中的内容读到char*中,调用StrAssign();
    Chunk *h = S.head, *p, *q;
    if (!h)
        return ERROR;
    T->head = (Chunk *)malloc(sizeof(Chunk)); //创建头节点
    p = T->head;
    *p = *h; //将S头节点的内容复制给T头节点
    h = h->next;
    while(h)
    {
        q = p;
        p = (Chunk *)malloc(sizeof(Chunk));
        q->next = p;
        *p = *h;
        h = h->next;
    }
    p->next = NULL;
    T->rear = p;
    return OK;
}
Status StrEmpty(LString S)
{
    if (!S.curlen)
        return TRUE;
    else
        return FALSE;
}
int StrCompare(LString S, LString T)
{
    int i = 0;
    Chunk *ps = S.head, *pt = T.head;
    while(ps && pt) //当有一个节点指向NULL时结束循环
    {
        for (i = 0; i < CHUNKSIZE; ++i) //节点内遍历
        {
            if (*(ps->ch + i) != *(pt->ch + i)) //如果指向的元素不同,则返回相减结果
            {
                if (*(ps->ch + i) == blank)
                    return -1;
                else if (*(pt->ch + i) == blank)
                    return 1;
                return *(ps->ch + i) - *(pt->ch + i);
            }
        }
        ps = ps->next; //该节点对比结束,进入下一节点对比
        pt = pt->next;
    }
    return ps - pt; //当有一个指向NULL时,该指针为0,返回相减结果即可
}
// int StrCompare(LString S, LString T) //书上源码
// {
//     /* 若S>T,则返回值>0;若S=T,则返回值=0;若S<T,则返回值<0 */
//     int i = 0; /* i为当前待比较字符在S,T串中的位置 */
//     Chunk *ps = S.head, *pt = T.head; /* ps,pt分别指向S和T的待比较块 */
//     int js = 0, jt = 0; /* js,jt分别指示S和T的待比较字符在块中的位序 */
//     while(i < S.curlen && i < T.curlen)
//     {
//         i++; /* 分别找S和T的第i个字符 */
//         while(*(ps->ch + js) == blank) /* 跳过填补空余的字符 */
//         {
//             js++;
//             if(js == CHUNKSIZE)
//             {
//                 ps = ps->next;
//                 js = 0;
//             }
//         }; /* *(ps->ch+js)为S的第i个有效字符 */
//         while(*(pt->ch + jt) == blank) /* 跳过填补空余的字符 */
//         {
//             jt++;
//             if(jt == CHUNKSIZE)
//             {
//                 pt = pt->next;
//                 jt = 0;
//             }
//         }; /* *(pt->ch+jt)为T的第i个有效字符 */
//         if(*(ps->ch + js) != *(pt->ch + jt))
//             return *(ps->ch + js) - *(pt->ch + jt);
//         else /* 继续比较下一个字符 */
//         {
//             js++;
//             if(js == CHUNKSIZE)
//             {
//                 ps = ps->next;
//                 js = 0;
//             }
//             jt++;
//             if(jt == CHUNKSIZE)
//             {
//                 pt = pt->next;
//                 jt = 0;
//             }
//         }
//     }
//     return S.curlen - T.curlen;
// }
int StrLength(LString S)
{
    return S.curlen;
}
Status ClearString(LString *S)
{
    Chunk *p, *q;
    if (!S->curlen)
        return ERROR;
    p = S->head;
    while(p)
    {
        q = p->next;
        free(p);
        p = q;
    }
    S->head = NULL;
    S->rear = NULL;
    S->curlen = 0;
    return OK;
}
Status Concat(LString *T, LString S1, LString S2)
{
    LString T1, T2;
    InitString(&T1);
    InitString(&T2);
    StrCopy(&T1, S1);
    StrCopy(&T2, S2);
    T->curlen = S1.curlen + S2.curlen;
    T->head = T1.head;
    T1.rear->next = T2.head;
    T->rear = T2.rear;
    return OK;
}
void StrPrint(LString T)
{
    Chunk *p;
    p = T.head;
    int i;
    while(p)
    {
        for (i = 0; i < CHUNKSIZE; ++i)
            if (*(p->ch + i) != blank)
                printf("%c", *(p->ch + i));
        p = p->next;
    }
    printf("\n");
}
void DestroyString() //无法销毁
{
    ;
}
Status StrInsert(LString *S, int pos, LString T) //书上源码
{
    /* 1≤pos≤StrLength(S)+1。在串S的第pos个字符之前插入串T */
    int i, j, k;
    Chunk *p, *q;
    LString t;
    if(pos < 1 || pos > StrLength(*S) + 1) /* pos超出范围 */
        return ERROR;
    StrCopy(&t, T); /* 复制T为t */
    Zip(S); /* 去掉S中多余的填补空余的字符 */
    i = (pos - 1) / CHUNKSIZE; /* 到达插入点要移动的块数 */
    j = (pos - 1) % CHUNKSIZE; /* 到达插入点在最后一块上要移动的字符数 */
    p = (*S).head;
    if(pos == 1) /* 插在S串前 */
    {
        t.rear->next = (*S).head;
        (*S).head = t.head;
    }
    else if(j == 0) /* 插在块之间 */
    {
        for(k = 1; k < i; k++)
            p = p->next; /* p指向插入点的左块 */
        q = p->next; /* q指向插入点的右块 */
        p->next = t.head; /* 插入t */
        t.rear->next = q;
        if(q == NULL) /* 插在S串后 */
            (*S).rear = t.rear; /* 改变尾指针 */
    }
    else /* 插在一块内的两个字符之间 */
    {
        for(k = 1; k <= i; k++)
            p = p->next; /* p指向插入点所在块 */
        q = (Chunk *)malloc(sizeof(Chunk)); /* 生成新块 */
        for(i = 0; i < j; i++)
            *(q->ch + i) = blank; /* 块q的前j个字符为填补空余的字符 */
        for(i = j; i < CHUNKSIZE; i++)
        {
            *(q->ch + i) = *(p->ch + i); /* 复制插入点后的字符到q */
            *(p->ch + i) = blank; /* p的该字符为填补空余的字符 */
        }
        q->next = p->next;
        p->next = t.head;
        t.rear->next = q;
    }
    (*S).curlen += t.curlen;
    Zip(S);
    return OK;
}
// Status StrInsert(LString *S, int pos, LString T) //插入字符串操作,有BUG
// {
//     //在块之间插入新的字符串,并利用zip压缩将串中多余的#去处
//     int i, j, insertPos, blockPos;
//     if (pos >= S->curlen) //如果pos越界,则定位在头或尾位置
//         pos = S->curlen + 2;
//     else if (pos <= 0)
//         return ERROR;
//     Chunk *h = S->head, *p, *q;
//     insertPos = pos % CHUNKSIZE; //确定块中要插入的位置
//     if (pos % CHUNKSIZE == 0) //如果插入的位置是块之间
//     {
//         blockPos = pos / CHUNKSIZE; //定位要插入块的位置
//         q = S->head; //q指向头结点
//         for (i = blockPos; i > 1; --i) //q指向正在被分开的块
//             q = q->next;
//     }
//     else //如果是块中
//     {
//         blockPos = (pos / CHUNKSIZE) + 1; //定位块
//         //将块要插入的位置前后分离
//         p = (Chunk *)malloc(sizeof(Chunk)); //申请一个新的结点,将插入点后的半个结点挪过去
//         q = S->head; //q指向头结点
//         for (i = blockPos; i > 1; --i) //q指向正在被分开的块
//             q = q->next;
//         j = i = CHUNKSIZE - (pos % CHUNKSIZE); //使用i,j来存储需要挪的个数(该结点从后往前数)
//         for (; i > 0; --i) //将有效字符挪到新节点中,对应原结点中的位置为#
//         {
//             *(p->ch + CHUNKSIZE - i) = *(q->ch + CHUNKSIZE - i);
//             *(q->ch + CHUNKSIZE - i) = blank;
//         }
//         for (; j < CHUNKSIZE; ++j)
//             *(p->ch + CHUNKSIZE - j - 1) = blank;
//         p->next = q->next; //将结点重新连接起来
//         q->next = p;
//     }
//     //此时需要在q之后插入新节点即可,插入完毕后压缩
//     T.rear->next = q->next;
//     q->next = T.head;
//     S->curlen += T.curlen;
//     Zip(S);
//     return OK;
// }
void Zip(LString *S) //压缩串
{
    int i, j = 0;
    char *q; //将字符串读入*q
    q = (char *)malloc(((*S).curlen + 1) * sizeof(char));
    Chunk *p = S->head;
    while(p)
    {
        for (i = 0; i < CHUNKSIZE; ++i)
            if (*(p->ch + i) != blank)
            {
                *(q + j) = *(p->ch + i);
                j++;
            }
        p = p->next;
    }
    *(q + j) = 0; //串结束符
    ClearString(S); //清空字符串S
    StrAssign(S, q); //将读入的字符串重新赋值给S
}
Status StrDelete(LString *S, int pos, int len) //删除长度为len的子串,将被删除的位置替换成为#再压缩即可
{
    if (pos > S->curlen || pos < 1 || pos + len > S->curlen)
        return ERROR;
    Chunk *p, *q;
    int i, j = 0, n = 0;
    p = S->head;
    pos--;
    while(n < pos)
    {
        j++;
        if (j == CHUNKSIZE)
        {
            p = p->next;
            j = 0;
        }
        n++;
    }
    while(n < pos + len)
    {
        *(p->ch + j) = blank;
        j++;
        if (j == CHUNKSIZE)
        {
            p = p->next;
            j = 0;
        }
        n++;
    }
    Zip(S);
    return OK;
}
Status SubString(LString *Sub, LString S, int pos, int len) //返回某位置长度为len的子串
{
    Chunk *p;
    char *q;
    if (pos > S.curlen || pos < 0 || pos + len - 1 > S.curlen)
        return ERROR;
    q = (char *)malloc((len + 1) * sizeof(char));
    int i = 0, j = 0, n;
    p = S.head;
    while(j < pos) //逐个位置索引到pos
    {
        if (j == pos - 1)
            break;
        ++j;
        ++i;
        if (i == CHUNKSIZE)
        {
            p = p->next;
            i = 0;
        }
    }
    j = 0;
    while(j < len) //逐个位置赋值
    {
        *(q + j) = *(p->ch + i);
        i++;
        if (i == CHUNKSIZE)
        {
            p = p->next;
            i = 0;
        }
        j++;
    }
    *(q + j) = 0;
    InitString(Sub); //初始化子串
    StrAssign(Sub, q); //将q中赋值
    Sub->curlen = len;
    return OK;
}
// Status SubString(LString *Sub, LString S, int pos, int len) //书上源码
// {
//     /* 用Sub返回串S的第pos个字符起长度为len的子串。 */
//     /* 其中,1≤pos≤StrLength(S)且0≤len≤StrLength(S)-pos+1 */
//     Chunk *p, *q;
//     int i, k, n, flag = 1;
//     if(pos < 1 || pos > S.curlen || len < 0 || len > S.curlen - pos + 1)
//         return ERROR;
//     n = len / CHUNKSIZE; /* 生成空的Sub串 */
//     if(len % CHUNKSIZE)
//         n++; /* n为块的个数 */
//     p = (Chunk *)malloc(sizeof(Chunk));
//     (*Sub).head = p;
//     for(i = 1; i < n; i++)
//     {
//         q = (Chunk *)malloc(sizeof(Chunk));
//         p->next = q;
//         p = q;
//     }
//     p->next = NULL;
//     (*Sub).rear = p;
//     (*Sub).curlen = len;
//     for(i = len % CHUNKSIZE; i < CHUNKSIZE; i++)
//         *(p->ch + i) = blank; /* 填充Sub尾部的多余空间 */
//     q = (*Sub).head; /* q指向Sub串即将复制的块 */
//     i = 0;  //i指示即将复制的字符在块中的位置
//     p = S.head; /* p指向S串的当前块 */
//     n = 0; /* n指示当前字符在串中的序号 */
//     while(flag)
//     {
//         for(k = 0; k < CHUNKSIZE; k++) /* k指示当前字符在块中的位置 */
//             if(*(p->ch + k) != blank)
//             {
//                 n++;
//                 if(n >= pos && n <= pos + len - 1) /* 复制 */
//                 {
//                     if(i == CHUNKSIZE)
//                     {
//                         /* 到下一块 */
//                         q = q->next;
//                         i = 0;
//                     }
//                     *(q->ch + i) = *(p->ch + k);
//                     i++;
//                     if(n == pos + len - 1) /* 复制结束 */
//                     {
//                         flag = 0;
//                         break;
//                     }
//                 }
//             }
//         p = p->next;
//     }
//     return OK;
// }
int Index(LString S, LString T, int pos) //在S中索引子串T
{
    int i, j;
    LString sub;
    if (pos < 1 || pos > S.curlen - T.curlen)
        return ERROR;
    while(pos <= S.curlen - T.curlen + 1)
    {
        SubString(&sub, S, pos, T.curlen);
        if (StrCompare(sub, T) == 0)
            return pos;
        else
            ++pos;
    }
    return ERROR;
}
Status Replace(LString *S, LString T, LString V) //将S中的T替换成V
{
    if (StrEmpty(T))
        return ERROR;
    int pos = 1;
    do
    {
        pos = Index(*S, T, pos);
        if (pos)
        {
            StrDelete(S, pos, T.curlen);
            StrInsert(S, pos, V);
            pos += V.curlen;
        }
    }
    while(pos);
    return OK;
}
