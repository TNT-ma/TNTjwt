<?php
return [
    'enable' => true,//启用
    'key' => '123456',//加密·密钥
    'field' => ["id","username"],//允许存入的字段 
    'iss' => 'http://www.baidu.com',//令牌签发者
    'exp' => 60 //令牌有效期 
];