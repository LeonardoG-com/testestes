<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Aqui podes registar as rotas da API para a tua aplicação. Estas
| rotas são carregadas pelo RouteServiceProvider e todas elas serão
| atribuídas ao grupo de middleware "api".
|
*/

/**
 * Rotas de Autenticação JWT
 * 
 * Estas rotas gerem todo o processo de autenticação usando JSON Web Tokens.
 * Todas as rotas têm o prefixo /api automaticamente.
 */
Route::group(['prefix' => 'auth'], function () {
    
    // Rotas públicas (não requerem autenticação)
    Route::post('/register', [AuthController::class, 'register'])->name('auth.register');
    Route::post('/login', [AuthController::class, 'login'])->name('auth.login');
    
    // Rotas protegidas (requerem autenticação JWT)
    Route::middleware('auth:api')->group(function () {
        Route::post('/logout', [AuthController::class, 'logout'])->name('auth.logout');
        Route::post('/refresh', [AuthController::class, 'refresh'])->name('auth.refresh');
        Route::get('/me', [AuthController::class, 'me'])->name('auth.me');
        Route::put('/profile', [AuthController::class, 'updateProfile'])->name('auth.profile');
        Route::put('/change-password', [AuthController::class, 'changePassword'])->name('auth.change-password');
    });
});

/**
 * Rota de exemplo protegida
 * 
 * Esta rota demonstra como proteger qualquer rota com autenticação JWT.
 * Só utilizadores autenticados podem aceder a esta rota.
 */
Route::middleware('auth:api')->get('/user', function (Request $request) {
    return response()->json([
        'status' => 'sucesso',
        'utilizador' => $request->user()
    ]);
})->name('user.current');

/**
 * Rotas de exemplo para demonstrar proteção de recursos
 * 
 * Estas rotas mostram como criar endpoints protegidos para uma API RESTful.
 */
Route::middleware('auth:api')->group(function () {
    
    // Exemplo de rota que retorna dados protegidos
    Route::get('/dados-protegidos', function () {
        return response()->json([
            'status' => 'sucesso',
            'mensagem' => 'Acesso a dados protegidos concedido!',
            'dados' => [
                'info' => 'Estes dados só são visíveis para utilizadores autenticados.',
                'timestamp' => now()->toISOString()
            ]
        ]);
    })->name('dados.protegidos');
    
});
