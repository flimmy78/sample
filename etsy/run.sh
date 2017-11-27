#!/bin/bash

TIME=2
SHOPNAME=AURAMORE
SHOPURL="https://www.etsy.com/shop/"$SHOPNAME
SOLDURL=$SHOPURL"/sold?ref=pagination&page="
STARTPAGE=$1
ENDPAGE=$2

#删除中间文件
rm -fr $SHOPNAME.txt
rm -fr cur.txt
rm -fr tmp.txt
rm -fr ${SHOPNAME}_uniq.html

#CURL检索数据:title和img
echo "Curl "
for((i=STARTPAGE;i<=ENDPAGE;i++)); 
do 
    echo "$SOLDURL$i"
    curl -s $SOLDURL$i  > curl.txt
    if [ $? -eq 0 ];then
        egrep "(^\s{8}title=)|(^\s{24}<img src=)" curl.txt | grep -o "\".*\"">> $SHOPNAME.txt
        sleep $TIME
    fi
done

#加入img标签和<br>标签
echo "Format"
awk '{tmp=$0;getline;print tmp"\t  <br><img src="$0"/><br>"}' $SHOPNAME.txt > tmp.txt
cp -fr tmp.txt  $SHOPNAME.txt

#排序，然后去重，行首加入产品销售数量，再重新排序
echo "Sort"
echo "$SHOPNAME.txt | uniq -c >> ${SHOPNAME}_uniq.html"
sort $SHOPNAME.txt | uniq -c > tmp.txt 

#加入总的销量
echo "Summary"
SUMMARY=`awk 'END { print NR }' ${SHOPNAME}.txt`
echo "总销量:$SUMMARY <br>" >>tmp.txt

echo "Resort"
sort -r tmp.txt > ${SHOPNAME}_uniq.html 

#删除中间文件
rm -fr cur.txt
rm -fr tmp.txt

echo "Finish"
