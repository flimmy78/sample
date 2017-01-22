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

   $sql = 'DROP DATABASE RUNOOB';
   $retval = mysql_query( $sql, $conn );
   if(! $retval )
   {
	   die('删除数据库失败: ' . mysql_error());
   }
   echo "数据库 RUNOOB 删除成功\n";

   mysql_close($conn);
?>
</body>
</html>
