#include <stdio.h>
#include <string.h>
#include <mysql.h>


int main()
{
    int ret = 0;
	MYSQL mysql;
	MYSQL_RES *res;
	MYSQL_ROW row;

    mysql_init (&mysql);


    MYSQL *mysqlhdl = NULL;

    //3306连接的是mysql本身, 3307连接的是sqlrelay
//mysqlhdl = mysql_real_connect (&mysql, "192.168.10.230", "root", "123456", "runoob", 3306, 0, 0);
    mysqlhdl = mysql_real_connect (&mysql, "192.168.10.230", "sqlruser", "sqlrpassword", "runoob", 3307, 0, 0);
    if (NULL == mysqlhdl)
    {
        fprintf (stderr, "mysql_real_connect failed\n");
        return 0;
    }
    else
    {
        fprintf (stdout, "connect mysql success\n");
    }

    char *sql = "insert into runoob_tbl (runoob_title, runoob_author, submission_date) VALUES (\"Learn Linux\", \"Da Fei\", Now())";
    ret =  mysql_real_query (&mysql, sql, strlen(sql));
    if (0 != ret)
    {
        fprintf (stderr, "mysql_real_query failed\n");
        return 0;
    }

    sql = "select * from runoob_tbl";
    ret =  mysql_real_query (&mysql, sql, strlen(sql));
    if (0 != ret)
    {
        fprintf (stderr, "mysql_real_query failed\n");
        return 0;
    }

    res = mysql_store_result (&mysql);
    if (NULL == res)
    {
        fprintf (stderr, "mysql_store_result failed\n");
        return 0;
    }

    unsigned int num_fields = mysql_num_fields (res);
    unsigned long *lengths = NULL;
    int i = 0;
    while ( row = mysql_fetch_row (res))
    {
        lengths = mysql_fetch_lengths (res);
        for (i = 0; i < num_fields; i++)
        {
            //printf ("%.*s  ", (int)lengths[i], row[i] ? row[i] : "NULL");
            printf ("%s  ", row[i] ? row[i] : "NULL");
        }
        printf ("\n");
    }

    mysql_free_result(res);
    mysql_close(&mysql);

	return 0;
}

