#include <stdio.h>
#include <string.h>
#include <sqlrelay/sqlrclientwrapper.h>


int main()
{
    sqlrcon con = sqlrcon_alloc("192.168.10.77",9000,NULL,"root","123456",0,1);
    if (NULL == con)
    {
        printf ("sqlrcon_alloc failed\n");
        return 1;
    }

    sqlrcur cur=sqlrcur_alloc(con);
    if (NULL == cur)
    {
        printf ("sqlrcur_alloc failed\n");
        return 1;
    }

    int ret = 0;
    ret = sqlrcur_sendQuery(cur,"select * from runoob_tbl");
    if (0 == ret)
    {
        printf ("sqlrcur_sendQuery failed, %s\n", sqlrcur_errorMessage(cur));
    }
    sqlrcon_endSession (con);

#if 1
    int i = 0;
    for (i=0; i<sqlrcur_colCount(cur); i++) {
        printf("Name:          %s\n",sqlrcur_getColumnName(cur,i));
        printf("Type:          %s\n",sqlrcur_getColumnTypeByIndex(cur,i));
        printf("Length:        %d\n",sqlrcur_getColumnLengthByIndex(cur,i));
        printf("Precision:     %d\n",sqlrcur_getColumnPrecisionByIndex(cur,i));
        printf("Scale:         %d\n",sqlrcur_getColumnScaleByIndex(cur,i));
        printf("Longest Field: %d\n",sqlrcur_getLongestByIndex(cur,i));
        printf("Nullable:      %d\n",sqlrcur_getColumnIsNullableByIndex(cur,i));
        printf("Primary Key:   %d\n",sqlrcur_getColumnIsPrimaryKeyByIndex(cur,i));
        printf("Unique:        %d\n",sqlrcur_getColumnIsUniqueByIndex(cur,i));
        printf("Part of Key:   %d\n",sqlrcur_getColumnIsPartOfKeyByIndex(cur,i));
        printf("Unsigned:      %d\n",sqlrcur_getColumnIsUnsignedByIndex(cur,i));
        printf("Zero Filled:   %d\n",sqlrcur_getColumnIsZeroFilledByIndex(cur,i));
        printf("Binary:        %d\n",sqlrcur_getColumnIsBinaryByIndex(cur,i));
        printf("Auth Increment:%d\n",sqlrcur_getColumnIsAutoIncrementByIndex(cur,i));
        printf("\n");
    }
#endif

    int row, col;
    int rowSum = sqlrcur_rowCount (cur);
    int colSum = sqlrcur_colCount (cur);
    for (row=0; row < rowSum; row++) {
        for (col=0; col < colSum; col++) {
            printf("%s ",sqlrcur_getFieldByIndex(cur,row,col));
        }
        printf("\n");
    }

#if 0
    ret = sqlrcur_getDatabaseList (cur, NULL);
    if ( 0 == ret)
    {
        printf ("sqlrcur_sendQuery failed, %s\n", sqlrcur_errorMessage(cur));
    }
    rowSum = sqlrcur_rowCount (cur);
    colSum = sqlrcur_colCount (cur);
    for (row=0; row < rowSum; row++) {
        for (col=0; col < colSum; col++) {
            printf("%s ",sqlrcur_getFieldByIndex(cur,row,col));
        }
        printf("\n");
    }
#endif


    sqlrcur_free (cur);
    sqlrcon_free (con);

    return 0;
}
      
 

