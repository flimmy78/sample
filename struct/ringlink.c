/*
https://www.cnblogs.com/xudong-bupt/p/3667729.html
其中第三条说法是有误的
第一次碰撞点Pos到连接点Join的距离 (可能包含多圈)=头指针到连接点Join的距离

*/


#include <stdio.h>
#include <stdlib.h>
typedef struct node{
    int value;
    struct node *next;
}LinkNode,*Linklist;

/// 创建链表(链表长度，环节点起始位置)
Linklist createList(){
    Linklist head = NULL;
    LinkNode *preNode = head;
    LinkNode *FifthNode = NULL;
    for(int i=0;i<6;i++){
        LinkNode *tt = (LinkNode*)malloc(sizeof(LinkNode));
        tt->value = i;
        tt->next = NULL;
        if(preNode == NULL){
            head = tt;
            preNode = head;
        }
        else{
            preNode->next =tt;
            preNode = tt;
        }

        if(i == 3)
            FifthNode = tt;
    }
    preNode->next = FifthNode;
    return head;
}

//若fast指针落后slow指针1个节点(就是前一个节点），那么再下一次if判断就能够遇上
//若fast指针落后slow指针2个节点, 那么while执行两次就能遇上
//若fast指针落后slow指针0个节点, 说明此时已经遇上
//总归之,fast的step=2，slow的step=1,fast指针肯定能够遇上slow指针；若fast指针的step > 2，则可能需要多次才能遇上或刚好越过
//这种情况下，就需要用if ((fast->next == slow) || (faster->next-> == slow))这种方式去提前预测，而不是偏移后比较两个
//指针是否相等来判断是否有环

///判断链表是否有环
LinkNode* judgeRing(Linklist list){
    LinkNode *fast = list;
    LinkNode *slow = list;

    if(list == NULL)
        return NULL;

    while(true){
        if(slow->next != NULL && fast->next != NULL && fast->next->next != NULL){
            slow = slow->next;
            fast = fast->next->next;
        }
        else
            return NULL;

        if(fast == slow)
            return fast;
    }
}

///获取链表环长
int getRingLength(LinkNode *ringMeetNode){
    int RingLength=0;
    LinkNode *fast = ringMeetNode;
    LinkNode *slow = ringMeetNode;
    for(;;){
        fast = fast->next->next;
        slow = slow->next;
        RingLength++;
        if(fast == slow)
            break;
    }
    return RingLength;
}

///获取链表头到环连接点的长度
int getLenA(Linklist list,LinkNode *ringMeetNode){
    int lenA=0;
    LinkNode *fast = list;
    LinkNode *slow = ringMeetNode;
    for(;;){
        fast = fast->next;
        slow = slow->next;
        lenA++;
        if(fast == slow)
            break;
    }
    return lenA;
}

///环起始点
///如果有环, 释放空空间时需要注意. 
LinkNode* RingStart(Linklist list, int lenA){
    if (!list || lenA <= 0){
        return NULL;
    }

    int i = 0;
    LinkNode* tmp = list;
    for ( ; i < lenA; ++i){
        if (tmp != NULL){
            tmp = tmp->next;
        }
    }

    return (i == lenA)? tmp : NULL;
}

///释放空间
int freeMalloc(Linklist list, LinkNode* ringstart){
    bool is_ringstart_free = false; //环起始点只能被释放空间一次
    LinkNode *nextnode = NULL;

    while(list != NULL){
        nextnode = list->next;
        if (list == ringstart){ //如果是环起始点
            if (is_ringstart_free)
                break;  //如果第二次遇到环起始点addr, 表示已经释放完成
            else
                is_ringstart_free = true;   //记录已经释放一次
        }
        free(list);
        list = nextnode;
    }

    return 0;
}

int main(){
    Linklist list = NULL;
    LinkNode *ringMeetNode  = NULL;
    LinkNode *ringStartNode = NULL;

    int LenA       = 0;
    int RingLength = 0;

    list = createList();
    ringMeetNode = judgeRing(list); //快慢指针相遇点

    if(ringMeetNode == NULL)
        printf("No Ring\n");
    else{
        printf("Have Ring\n");
        RingLength = getRingLength(ringMeetNode);   //环长
        LenA = getLenA(list,ringMeetNode);

        printf("RingLength:%d\n", RingLength);
        printf("LenA:%d\n", LenA);
        printf("listLength=%d\n", RingLength+LenA);
    }

    ringStartNode = RingStart(list, LenA);  //获取环起始点
    freeMalloc(list, ringStartNode);    //释放环节点, 有环时需要注意. 采纳5楼建议
    return 0;
}
