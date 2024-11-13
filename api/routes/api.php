<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\JWTAuthController;
use App\Http\Controllers\PostController;
use App\Http\Middleware\JwtMiddleware;

Route::apiResource('posts', PostController::class);

Route::post('register', [JWTAuthController::class, 'register']);
Route::post('login', [JWTAuthController::class, 'login']);

Route::post('logout', [JWTAuthController::class, 'logout'])->middleware('jwt.auth');

Route::middleware([JwtMiddleware::class])->group(function () {
    Route::get('user', [JWTAuthController::class, 'getUser']);
});
