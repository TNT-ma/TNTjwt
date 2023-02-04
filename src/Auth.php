<?php

declare(strict_types=1);
namespace Tntma\Tntjwt;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Tntma\Tntjwt\Exception\TntException;

use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException; 
use UnexpectedValueException;

class Auth{ 
    
    public static  function user($cache = false) {  
        
        $key = config('plugin.Tntma.tntjwt.app.key'); //key  
        $Authorization = request()->header('Authorization', ''); 
        if(empty($Authorization)){
            return null; 
        }
         if(strpos($Authorization,'Bearer ') === false){
             return null;
         }
        
        $token = str_replace("Bearer ","",$Authorization);
         
        
        try {
            $decoded = JWT::decode($token, new Key($key, 'HS256')); 
            return $decoded->extend;//返回令牌内的数据 
        } catch(SignatureInvalidException $e) {
            echo "\nJwt-user:身份验证令牌无效\n";
            return null;
            #throw new TntException('身份验证令牌无效',401);
        }catch(BeforeValidException $e) { // 签名在某个时间点之后才能用
            echo "\nJwt-user:身份验证令牌尚未生效\n";
            return null;
            #throw new TntException('身份验证令牌尚未生效',403);
        }catch(ExpiredException $e) { // token过期
            echo "\nJwt-user:身份验证会话已过期，请重新登录！\n";
            return null;
            #throw new TntException('身份验证会话已过期，请重新登录！',402);
        } catch (UnexpectedValueException $unexpectedValueException) {
            echo "\nJwt-user:获取扩展字段不正确\n";
            return null;
            #throw new TntException('获取扩展字段不正确',401);
        } catch (\Exception $exception) {
            echo "\nJwt-user:".$exception->getMessage()."\n";
            return null;
            #throw new TntException($exception->getMessage(),401);
        }
            
    }
    
    public static  function login($data){
        $fields = config('plugin.Tntma.tntjwt.app.field'); //允许使用的数据
        $kkey = config('plugin.Tntma.tntjwt.app.key'); //key  
        $exp = config('plugin.Tntma.tntjwt.app.exp'); //key 
        $iss = config('plugin.Tntma.tntjwt.app.iss'); //key 
        
         
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
            'iss' => $iss,
            'iat' => time(),  
            'exp' => time() + $exp, //过期时间
            'extend' => $newData
            ];
            
            $encode = JWT::encode($basePayload, $kkey, 'HS256'); 
            return json_decode(json_encode([
            'token_type' => 'Bearer',
            'token_md5' => md5('Bearer '.$encode), 
            'expires_in' => time() + $exp,
            'refresh_expires_in' => "未支持",
            'access_token' => $encode,
            'refresh_token' => "未支持",
        ]));
            return $encode;  
        }catch (SignatureInvalidException $e){
            throw new tntException("jwt生成失败:".$e->getMessage()); 
        }
    }
    
}