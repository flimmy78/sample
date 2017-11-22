<html>
<head>
<meta charset="utf-8"> 
<title>Connecting MySQL Server</title>
</head>
<body>
<?php
$dbhost = 'localhost:3306';
$dbuser = 'root';
$dbpass = '123456';
$conn = mysql_connect($dbhost, $dbuser, $dbpass);
if(! $conn )
{
    die('Could not connect: ' . mysql_error());
}
$sql = 'SELECT * FROM zenzet';

mysql_select_db('runoob');
$retval = mysql_query( $sql, $conn );
if(! $retval )
{
    die('Could not get data: ' . mysql_error());
}
echo "<h1>This is MySQL Result </h1><br>";
while($row = mysql_fetch_array($retval, MYSQL_NUM))
{
    echo "ID :{$row[0]}  <br> ".
        "Name: {$row[1]} <br> ".
        "Age: {$row[2]} <br> ".
        "--------------------------------<br>";
}
mysql_free_result($retval);
echo "Fetched data successfully\n";
mysql_close($conn);
?>
</body>
</html>
