<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\UpdatePasswordRequest;
use App\Http\Requests\UpdateProfileRequest;
use App\Traits\ApiResponse;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Cache\Console\ForgetCommand;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

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

    public function profileUpdate(UpdateProfileRequest $request)
    {
        try{
            $user = Auth::user();
            if (!$user) {
                return $this->error('User not found', 404);
            }
            
            $user->name = $request->name;
            $user->email = $request->email;
            $user->save();
            return $this->success($user, 'User profile updated successfully', 200);
        }catch(\Exception $e){
            Log::error('User profile update failed: ' . $e->getMessage(). ' at line ' . $e->getLine());
            return $this->error('User profile update failed', 500);
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

    public function passwordUpdate(UpdatePasswordRequest $request)
    {
        try{
            $user = Auth::user();
            if (!$user) {
                return $this->error('User not found', 404);
            }

            if(!Hash::check($request->old_password, $user->password)){
                return $this->error('Old password is incorrect', 401);
            }
            $user->password = Hash::make($request->new_password);
            $user->save();
            return $this->success($user, 'User password updated successfully', 200);
        }catch(\Exception $e){
            Log::error('User password update failed: ' . $e->getMessage(). ' at line ' . $e->getLine());
            return $this->error('User password update failed', 500);
        }
    }

    public function forgotPassword(ForgotPasswordRequest $request)
    {
        try{
            $email = $request->email;
            $user = User::where('email', $email)->first();
            if (!$user) {
                return $this->error('User not found', 404);
            }
            $token = $user->createToken('auth_token')->plainTextToken;

            // Send password reset link to user
            Mail::to($user->email)->send(new \App\Mail\PasswordResetLink($user, $token));

            return $this->success(['token' => $token], 'Password reset link sent successfully', 200);
        }catch(\Exception $e){
            Log::error('Password reset link send failed: ' . $e->getMessage(). ' at line ' . $e->getLine());
            return $this->error('Password reset link send failed', 500);
        }
    }
}
