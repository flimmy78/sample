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

   mysql_close($conn);
?>
</body>
</html>
