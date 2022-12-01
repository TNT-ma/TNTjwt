<?php

declare(strict_types=1);
namespace Webmans\Tntjwt;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Webmans\Tntjwt\Exception\TntException;
use Firebase\JWT\SignatureInvalidException;



class Auth{ 
    
    public static  function user($cache = false) {  
        
        $key = config('plugin.webmans.tntjwt.app.key'); //key  
        $Authorization = request()->header('Authorization', ''); 
        if(empty($Authorization)){
            throw new tntException('请求头缺少Authorization');  
        }
         if(strpos($Authorization,'Bearer ') === false){
             throw new tntException('Authorization中缺少：Bearer '); 
         }
        
        $token = str_replace("Bearer ","",$Authorization);
         
        
        try {
            $decoded = JWT::decode($token, new Key($key, 'HS256')); 
            return $decoded->extend;//返回令牌内的数据
            
        }catch (SignatureInvalidException $e){
            throw new tntException("jwt读取数据失败:".$e->getMessage()); 
        }
            
    }
    
    public static  function login($data){
        $fields = config('plugin.webmans.tntjwt.app.field'); //允许使用的数据
        $kkey = config('plugin.webmans.tntjwt.app.key'); //key  
        $exp = config('plugin.webmans.tntjwt.app.exp'); //key 
        $iss = config('plugin.webmans.tntjwt.app.iss'); //key 
        
         
        if(count($fields) > 0){
            $newData = [];
            // 过滤存储数据
            if(is_object($data)){
                foreach ($fields as $key){
                    if(isset($data->$key)){
                        $newData[$key] = $data->$key;
                    }
                }
            }elseif(is_array($data) && count($data) > 0){
                foreach ($fields as $key){
                    if(isset($data[$key])){
                        $newData[$key] = $data[$key];
                    }
                }
            } 
            
        }else{
            $newData = $data;
        }  
        
       
        
        try {
            $basePayload = [
            'iss' => 'http://www.yintaipay.com',
            'iat' => time(),  
            'exp' => time() + 3600, //过期时间
            'extend' => $newData
            ];
            
            $encode = JWT::encode($basePayload, $kkey, 'HS256'); 
            return json_decode(json_encode([
            'token_type' => 'Bearer',
            'expires_in' => 0,
            'refresh_expires_in' => "",
            'access_token' => $encode,
            'refresh_token' => "",
        ]));
            return $encode;  
        }catch (SignatureInvalidException $e){
            throw new tntException("jwt生成失败:".$e->getMessage()); 
        }
    }
    
}