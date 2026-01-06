<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    /**
     * Registar um novo utilizador.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     * 
     * Exemplo de requisição POST para /api/register:
     * {
     *     "name": "João Silva",
     *     "email": "joao@exemplo.com",
     *     "password": "password123",
     *     "password_confirmation": "password123"
     * }
     */
    public function register(Request $request)
    {
        // Validar os dados do pedido
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ], [
            // Mensagens de erro personalizadas em português
            'name.required' => 'O nome é obrigatório.',
            'name.max' => 'O nome não pode ter mais de 255 caracteres.',
            'email.required' => 'O email é obrigatório.',
            'email.email' => 'O email deve ser um endereço válido.',
            'email.unique' => 'Este email já está registado.',
            'password.required' => 'A palavra-passe é obrigatória.',
            'password.min' => 'A palavra-passe deve ter pelo menos 6 caracteres.',
            'password.confirmed' => 'A confirmação da palavra-passe não coincide.',
        ]);

        // Se a validação falhar, retornar erros
        if ($validator->fails()) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Erro de validação',
                'erros' => $validator->errors()
            ], 422);
        }

        // Criar o novo utilizador
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Gerar o token JWT para o novo utilizador
        $token = JWTAuth::fromUser($user);

        // Retornar resposta de sucesso com o utilizador e token
        return response()->json([
            'status' => 'sucesso',
            'mensagem' => 'Utilizador registado com sucesso',
            'utilizador' => $user,
            'autorizacao' => [
                'token' => $token,
                'tipo' => 'bearer',
            ]
        ], 201);
    }

    /**
     * Autenticar um utilizador e retornar um token JWT.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     * 
     * Exemplo de requisição POST para /api/login:
     * {
     *     "email": "joao@exemplo.com",
     *     "password": "password123"
     * }
     */
    public function login(Request $request)
    {
        // Validar os dados do pedido
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ], [
            'email.required' => 'O email é obrigatório.',
            'email.email' => 'O email deve ser um endereço válido.',
            'password.required' => 'A palavra-passe é obrigatória.',
        ]);

        // Se a validação falhar, retornar erros
        if ($validator->fails()) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Erro de validação',
                'erros' => $validator->errors()
            ], 422);
        }

        // Obter credenciais do pedido
        $credentials = $request->only('email', 'password');

        try {
            // Tentar autenticar e obter token
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    'status' => 'erro',
                    'mensagem' => 'Credenciais inválidas. Verifique o seu email e palavra-passe.',
                ], 401);
            }
        } catch (JWTException $e) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Não foi possível criar o token. Tente novamente.',
            ], 500);
        }

        // Retornar resposta de sucesso com o token
        return response()->json([
            'status' => 'sucesso',
            'mensagem' => 'Login efetuado com sucesso',
            'utilizador' => Auth::user(),
            'autorizacao' => [
                'token' => $token,
                'tipo' => 'bearer',
                'expira_em' => JWTAuth::factory()->getTTL() * 60 // tempo em segundos
            ]
        ]);
    }

    /**
     * Terminar sessão do utilizador (invalidar o token).
     *
     * @return \Illuminate\Http\JsonResponse
     * 
     * Requisição POST para /api/logout
     * Header: Authorization: Bearer {token}
     */
    public function logout()
    {
        try {
            // Invalidar o token atual
            JWTAuth::invalidate(JWTAuth::getToken());
            
            return response()->json([
                'status' => 'sucesso',
                'mensagem' => 'Sessão terminada com sucesso'
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Não foi possível terminar a sessão. Tente novamente.',
            ], 500);
        }
    }

    /**
     * Atualizar o token JWT (refresh).
     *
     * @return \Illuminate\Http\JsonResponse
     * 
     * Requisição POST para /api/refresh
     * Header: Authorization: Bearer {token}
     */
    public function refresh()
    {
        try {
            $novoToken = JWTAuth::refresh(JWTAuth::getToken());
            
            return response()->json([
                'status' => 'sucesso',
                'mensagem' => 'Token atualizado com sucesso',
                'autorizacao' => [
                    'token' => $novoToken,
                    'tipo' => 'bearer',
                    'expira_em' => JWTAuth::factory()->getTTL() * 60
                ]
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Não foi possível atualizar o token. Faça login novamente.',
            ], 401);
        }
    }

    /**
     * Obter os dados do utilizador autenticado.
     *
     * @return \Illuminate\Http\JsonResponse
     * 
     * Requisição GET para /api/me
     * Header: Authorization: Bearer {token}
     */
    public function me()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            
            if (!$user) {
                return response()->json([
                    'status' => 'erro',
                    'mensagem' => 'Utilizador não encontrado',
                ], 404);
            }

            return response()->json([
                'status' => 'sucesso',
                'utilizador' => $user
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Token inválido ou expirado',
            ], 401);
        }
    }

    /**
     * Atualizar o perfil do utilizador autenticado.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     * 
     * Exemplo de requisição PUT para /api/profile:
     * {
     *     "name": "João Silva Atualizado",
     *     "email": "joao.novo@exemplo.com"
     * }
     */
    public function updateProfile(Request $request)
    {
        /** @var User $user */
        $user = Auth::user();

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|string|email|max:255|unique:users,email,' . $user->id,
        ], [
            'name.max' => 'O nome não pode ter mais de 255 caracteres.',
            'email.email' => 'O email deve ser um endereço válido.',
            'email.unique' => 'Este email já está registado por outro utilizador.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Erro de validação',
                'erros' => $validator->errors()
            ], 422);
        }

        // Atualizar apenas os campos fornecidos
        if ($request->has('name')) {
            $user->name = $request->name;
        }
        if ($request->has('email')) {
            $user->email = $request->email;
        }

        $user->save();

        return response()->json([
            'status' => 'sucesso',
            'mensagem' => 'Perfil atualizado com sucesso',
            'utilizador' => $user
        ]);
    }

    /**
     * Alterar a palavra-passe do utilizador autenticado.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     * 
     * Exemplo de requisição PUT para /api/change-password:
     * {
     *     "current_password": "password123",
     *     "password": "novapassword456",
     *     "password_confirmation": "novapassword456"
     * }
     */
    public function changePassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'current_password' => 'required|string',
            'password' => 'required|string|min:6|confirmed',
        ], [
            'current_password.required' => 'A palavra-passe atual é obrigatória.',
            'password.required' => 'A nova palavra-passe é obrigatória.',
            'password.min' => 'A nova palavra-passe deve ter pelo menos 6 caracteres.',
            'password.confirmed' => 'A confirmação da palavra-passe não coincide.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'Erro de validação',
                'erros' => $validator->errors()
            ], 422);
        }

        /** @var User $user */
        $user = Auth::user();

        // Verificar se a palavra-passe atual está correta
        if (!Hash::check($request->current_password, $user->password)) {
            return response()->json([
                'status' => 'erro',
                'mensagem' => 'A palavra-passe atual está incorreta.',
            ], 401);
        }

        // Atualizar a palavra-passe
        $user->password = Hash::make($request->password);
        $user->save();

        return response()->json([
            'status' => 'sucesso',
            'mensagem' => 'Palavra-passe alterada com sucesso'
        ]);
    }
}
