<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use App\Traits\ApiResponse;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Log;

class AuthController extends Controller
{
    use ApiResponse;
    public function register(RegisterRequest $request)
    {
        try{
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
            return $this->success($user, 'User registered successfully', 201);
        }catch(\Exception $e){
            Log::error('User registration failed: ' . $e->getMessage(). ' at line ' . $e->getLine());
            return $this->error('User registration failed', 500);
        }
    }

    public function login(LoginRequest $request)
    {
        try{
            $credentials = $request->only('email', 'password');
            if (Auth::attempt($credentials)) {
                $user = Auth::user();
                $token = $user->createToken('auth_token')->plainTextToken;
                return $this->success(['token' => $token], 'User logged in successfully', 200);
            } else {
                return $this->error('Invalid credentials', 401);
            }
        }catch(\Exception $e){
            Log::error('User login failed: ' . $e->getMessage(). ' at line ' . $e->getLine());
            return $this->error('User login failed', 500);
        }
    }

    public function profile()
    {
        try{
            $user = Auth::user();
            if (!$user) {
                return $this->error('User not found', 404);
            }
            return $this->success($user, 'User profile retrieved successfully', 200);
        }catch(\Exception $e){
            Log::error('User profile retrieval failed: ' . $e->getMessage(). ' at line ' . $e->getLine());
            return $this->error('User profile retrieval failed', 500);
        }
    }

    public function logout()
    {
        try{
            $user = Auth::user();
            if (!$user) {
                return $this->error('User not found', 404);
            }
            $user->tokens()->delete();
            return $this->success([], 'User logged out successfully', 200);
        }catch(\Exception $e){
            Log::error('User logout failed: ' . $e->getMessage(). ' at line ' . $e->getLine());
            return $this->error('User logout failed', 500);
        }
    }
}
