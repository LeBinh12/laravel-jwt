<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','refresh']]);
    }

    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }


        $refreshToken = $this->createRefreshToken();

        return $this->respondWithToken($token,$refreshToken);
    }
    public function profile(){
        try{
            return response()->json(auth('api')->user());
        } catch(JWTException $exception){
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        
    }
    public function logout()
    {
        auth('api')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }
    public function refresh()
    {
        $refresh = request()->refresh_token;
        try{
            $decode = JWTAuth::getJWTProvider()->decode($refresh);
            #lấy token mới
            $user = User::find($decode["sub"]);
            if(!$user){
                return response()->json(['error' =>"User not found"],404);
            }
            $token = auth("api")->login($user);
            $refreshToken = $this->createRefreshToken();
            return $this->respondWithToken($token,$refreshToken);
        } catch (JWTException $exception){
            return response()->json(['error' => 'Refresh Token Invalid'],500);
        }

        
        //return $this->respondWithToken(auth('api')->refresh());
    }

    private function createRefreshToken(){
        $data = [
            'sub'=> auth('api')->user()->id,
            'random' => rand() . time(),
            'exp' => time() + config('jwt.refresh_ttl')
        ];

        $refreshToken = JWTAuth::getJWTProvider()->encode($data);
        return $refreshToken;
        
    }
    private function respondWithToken($token, $refreshToken)
    {
        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }
}
