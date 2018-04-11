string1 = "Lua";
print(string.upper(string1))
print(string.lower(string1))

sql = [[select * from table where name = 'gjc']]
print (sql)
sql = string.gsub(sql,'gjc','%lktencrypt$')
print (sql)


print (string.find("Hello Lua user", "Lua", 1))

sql = [[select * from table where name = 'gjc']]
print (string.reverse(sql))


print (string.format("the value is:%d",4))


print (string.char(97,98,99,100))

print (string.byte("abcd",4))

-- 初始化数组
array = {}
for i=1,3 do
   array[i] = {}
      for j=1,3 do
         array[i][j] = i*j
      end
end

-- 访问数组
for i=1,3 do
   for j=1,3 do
      print(array[i][j])
   end
end


-- table操作
mytable = {}
print("mytable 的类型是 ",type(mytable))

mytable[1]= "Lua"
mytable[2]= "lua"

print (table.concat(mytable, '||'))
table.insert(mytable, 'hello')

print (table.concat(mytable, '||'))
