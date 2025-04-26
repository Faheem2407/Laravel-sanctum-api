<?php

use App\Http\Controllers\Api\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


Route::controller(AuthController::class)->group(function () {
    Route::post('/register', 'register');
    Route::post('/login', 'login');
    Route::post('/logout', 'logout')->middleware('auth:sanctum');
    Route::get('/profile', 'profile')->middleware('auth:sanctum');
    Route::post('/profile-update', 'profileUpdate')->middleware('auth:sanctum');
    Route::post('/password-update', 'passwordUpdate')->middleware('auth:sanctum');
    Route::post('/forgot-password', 'forgotPassword')->middleware('auth:sanctum')->name('password.reset');
});