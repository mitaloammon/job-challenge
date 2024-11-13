<?php

namespace App\Http\Controllers;

use App\Http\Requests\UserRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class JWTAuthController extends Controller
{

    public function register(UserRequest $request)
    {

        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $token = JWTAuth::fromUser($user);

        return ['user' => $user, 'token' => $token];
    }


    public function login(UserRequest $request)
    {
        
        $user = User::where('email', $request->email)->first();
        $credentials = $request->only('email', 'password');


        if (! $token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Invalid credentials'], 401);
        }

        $user = auth()->user();

        $token = JWTAuth::claims(['role' => $user->role])->fromUser($user);

        return response()->json(compact('token'));
      
    }

    public function getUser()
    {

        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (JWTException $e) {
            return response()->json(['error' => 'Invalid token'], 400);
        }

        return response()->json(compact('user'));
    }

    public function logout(Request $request)
    {
        
        JWTAuth::invalidate(JWTAuth::getToken());
        
        return response()->json(['message' => 'Successfully logged out']);
    }
}
