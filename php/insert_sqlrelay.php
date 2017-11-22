<html>
<head>
<meta charset="utf-8"> 
<title>向 SQL Relay 添加数据</title>
</head>
<body>
<?php
if(isset($_POST['add']))
{
	$dbhost = '192.168.10.153:3307';
	$dbuser = '1234';
	$dbpass = '1234';
	$conn = mysql_connect($dbhost, $dbuser, $dbpass);
	if(! $conn )
	{
		die('Could not connect: ' . mysql_error());
	}

	if(! get_magic_quotes_gpc() )
	{
		$name = addslashes ($_POST['name']);
		$age = addslashes ($_POST['age']);
	}
	else
	{
		$name = $_POST['name'];
		$age = $_POST['age'];
	}

	$sql = "INSERT INTO zenzet ".
		"(name,age) ".
		"VALUES ".
		"('$name',$age)";
	mysql_select_db('runoob');
	$retval = mysql_query( $sql, $conn );
	if(! $retval )
	{
		die('Could not enter data: ' . mysql_error());
	}
	echo "Entered data successfully\n";
	mysql_close($conn);
}
else
{
?>
<form method="post" action="<?php $_PHP_SELF ?>">
<table width="600" border="0" cellspacing="1" cellpadding="2">
<h1>向SQL Relay写入(Insert Into操作)</h1>
<tr>
<td width="250">Name</td>
<td>
<input name="name" type="text" id="name">
</td>
</tr>
<tr>
<td width="250">Age</td>
<td>
<input name="age" type="text" id="age">
</td>
</tr>
<tr>
<td width="250"> </td>
<td> </td>
</tr>
<tr>
<td width="250"> </td>
<td>
<input name="add" type="submit" id="add" value="Add User">
</td>
</tr>
</table>
</form>
<?php
}
?>
</body>
</html>
