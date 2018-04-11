-- --[[ --]]用法，块注释
--[[
  test.lua
  author:guojianchuan
  data type: 1) nil 2) boolean 3) number 4) string 5) function 6) userdata 7) thread 8)table
--]]


-- require
local math = require("math")
local abs = math.abs
print (abs(-1.1))


-- [[]]用法
html = [[
  <html>
  <head></head>
  <body>
  <a href="//www.w3cschool.cn/">w3cschoolW3Cschool教程</a>
  </body>
  </html>
]]
print(html)

-- 字符串连接
print ("hello".."world")
print (11 .. 22) --11和22也可以连接， 但是在..的前后需要加入空格
print (type(11 .. 22)) --返回string

-- 计算字符串长度
str = "www.baidu.com"
print (#str)

-- table初始化
-- 方法1
local tbl = {} --空表
tbl.name = "guojianchuan"
tbl.age = 32
print (tbl['name']) --访问table的两种方式
print (tbl.age)

-- 方法2:没有key
local tbl = {"hello,world", "xxx"} --直接初始化
print (tbl[1]) --没有key的时候，只能用下标访问

-- 方法3:初始化的时候，用kv结构
local tbl = {name="name hello,world", age=32} --直接初始化
print (tbl.name) 


-- 遍历table
for k, v in pairs (tbl) do
  print (k.." : "..v)
end
