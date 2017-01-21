<html>
<head>
<meta charset="utf-8"> 
<title>Connecting MySQL Server</title>
</head>
<body>
<?php
   $dbhost = 'localhost:80';  //mysql服务器主机地址
   $dbuser = 'root';      //mysql用户名
   $dbpass = '123456';//mysql用户名密码
   $conn = mysql_connect($dbhost, $dbuser, $dbpass);
   if(! $conn )
   {
     die('Could not connect: ' . mysql_error());
   }
   echo 'Connected successfully';

   $retval = mysql_select_db('RUNOOB');
   if(! $retval )
   {
	   die('选择数据库失败: ' . mysql_error());
   }
   echo "数据库 RUNOOB 选择成功\n";

   $sql = "CREATE TABLE runoob_tbl( ".
       "runoob_id INT NOT NULL AUTO_INCREMENT, ".
       "runoob_title VARCHAR(100) NOT NULL, ".
       "runoob_author VARCHAR(40) NOT NULL, ".
       "submission_date DATE, ".
       "PRIMARY KEY ( runoob_id )); ";
   $retval = mysql_query( $sql, $conn );
   if(! $retval )
   {
         die('数据表创建失败: ' . mysql_error());
   }
   echo "数据表创建成功\n";

   mysql_close($conn);
?>
</body>
</html>
