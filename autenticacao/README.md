# Autenticação JWT com Laravel

## Índice

1. [Introdução](#introdução)
2. [O que é JWT?](#o-que-é-jwt)
3. [Estrutura de um Token JWT](#estrutura-de-um-token-jwt)
4. [Pré-requisitos](#pré-requisitos)
5. [Instalação e Configuração](#instalação-e-configuração)
6. [Configuração do Projeto](#configuração-do-projeto)
7. [Endpoints da API](#endpoints-da-api)
8. [Exemplos de Utilização](#exemplos-de-utilização)
9. [Testar com cURL](#testar-com-curl)
10. [Testar com Postman](#testar-com-postman)
11. [Boas Práticas de Segurança](#boas-práticas-de-segurança)
12. [Resolução de Problemas](#resolução-de-problemas)
13. [Recursos Adicionais](#recursos-adicionais)

---

## Introdução

Este projeto demonstra como implementar autenticação baseada em **JSON Web Tokens (JWT)** numa aplicação Laravel. A autenticação JWT é especialmente útil para:

- **APIs RESTful**: Onde não existe estado de sessão entre pedidos
- **Aplicações SPA (Single Page Applications)**: React, Vue.js, Angular
- **Aplicações móveis**: iOS, Android
- **Microserviços**: Comunicação entre serviços

### Vantagens do JWT sobre Sessions

| Característica | Sessions | JWT |
|---------------|----------|-----|
| Estado no servidor | Sim (stateful) | Não (stateless) |
| Escalabilidade | Limitada | Excelente |
| Cross-domain | Difícil | Fácil |
| Mobile-friendly | Não | Sim |

---

## O que é JWT?

**JSON Web Token (JWT)** é um padrão aberto (RFC 7519) que define uma forma compacta e autossuficiente de transmitir informações de forma segura entre duas partes como um objeto JSON.

### Quando usar JWT?

1. **Autenticação**: Após o login, cada pedido subsequente incluirá o JWT, permitindo ao utilizador aceder a rotas, serviços e recursos permitidos com esse token.

2. **Troca de Informação**: Os JWTs são uma boa forma de transmitir informação de forma segura entre partes, pois podem ser assinados digitalmente.

---

## Estrutura de um Token JWT

Um JWT é composto por três partes separadas por pontos (`.`):

```
xxxxx.yyyyy.zzzzz
```

### 1. Header (Cabeçalho)

Contém o tipo de token e o algoritmo de assinatura utilizado.

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### 2. Payload (Carga Útil)

Contém as **claims** (declarações). Existem três tipos:

- **Registered claims**: Claims pré-definidos como `iss` (issuer), `exp` (expiration time), `sub` (subject), `aud` (audience)
- **Public claims**: Definidos à vontade, mas devem ser registados para evitar colisões
- **Private claims**: Claims personalizados criados para partilhar informação

```json
{
  "sub": "1234567890",
  "name": "João Silva",
  "iat": 1516239022
}
```

### 3. Signature (Assinatura)

A assinatura é criada utilizando o header codificado, o payload codificado, uma chave secreta e o algoritmo especificado no header.

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### Exemplo de um Token JWT Completo

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvYW8gU2lsdmEiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

---

## Pré-requisitos

Antes de começar, certifica-te de que tens instalado:

- **PHP** >= 8.2
- **Composer** (gestor de dependências PHP)
- **Laravel** 12.x
- **Base de dados** (MySQL, PostgreSQL, SQLite, etc.)

### Verificar versões instaladas

```bash
php --version
composer --version
```

---

## Instalação e Configuração

### Passo 1: Instalar o pacote tymon/jwt-auth

```bash
composer require tymon/jwt-auth
```

### Passo 2: Publicar a configuração

Este comando copia o ficheiro de configuração para `config/jwt.php`:

```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

### Passo 3: Gerar a chave secreta JWT

Esta chave é usada para assinar os tokens. É adicionada automaticamente ao ficheiro `.env`:

```bash
php artisan jwt:secret
```

Resultado no `.env`:
```
JWT_SECRET=a_tua_chave_secreta_gerada_automaticamente
```

### Passo 4: Executar as migrações

```bash
php artisan migrate
```

---

## Configuração do Projeto

### Ficheiro: config/auth.php

O guard `api` deve ser configurado para usar o driver `jwt`:

```php
'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],

'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],

    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```

### Ficheiro: app/Models/User.php

O modelo User deve implementar a interface `JWTSubject`:

```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    // Métodos obrigatórios da interface JWTSubject

    /**
     * Obtém o identificador que será armazenado no claim "sub" do JWT.
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Retorna um array com claims personalizados a adicionar ao JWT.
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
```

### Ficheiro: config/jwt.php (Opções Importantes)

```php
// Tempo de vida do token em minutos (padrão: 60 minutos)
'ttl' => env('JWT_TTL', 60),

// Tempo de refresh do token em minutos (padrão: 2 semanas)
'refresh_ttl' => env('JWT_REFRESH_TTL', 20160),

// Algoritmo de assinatura
'algo' => env('JWT_ALGO', 'HS256'),
```

---

## Endpoints da API

### Resumo dos Endpoints

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| POST | `/api/auth/register` | Registar novo utilizador | Não |
| POST | `/api/auth/login` | Autenticar utilizador | Não |
| POST | `/api/auth/logout` | Terminar sessão | Sim |
| POST | `/api/auth/refresh` | Renovar token | Sim |
| GET | `/api/auth/me` | Obter dados do utilizador | Sim |
| PUT | `/api/auth/profile` | Atualizar perfil | Sim |
| PUT | `/api/auth/change-password` | Alterar palavra-passe | Sim |

### Detalhes de Cada Endpoint

#### 1. Registar Utilizador

**Endpoint:** `POST /api/auth/register`

**Headers:**
```
Content-Type: application/json
Accept: application/json
```

**Body:**
```json
{
    "name": "João Silva",
    "email": "joao@exemplo.com",
    "password": "password123",
    "password_confirmation": "password123"
}
```

**Resposta de Sucesso (201):**
```json
{
    "status": "sucesso",
    "mensagem": "Utilizador registado com sucesso",
    "utilizador": {
        "id": 1,
        "name": "João Silva",
        "email": "joao@exemplo.com",
        "created_at": "2024-01-15T10:30:00.000000Z",
        "updated_at": "2024-01-15T10:30:00.000000Z"
    },
    "autorizacao": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "tipo": "bearer"
    }
}
```

**Resposta de Erro (422):**
```json
{
    "status": "erro",
    "mensagem": "Erro de validação",
    "erros": {
        "email": ["Este email já está registado."],
        "password": ["A palavra-passe deve ter pelo menos 6 caracteres."]
    }
}
```

---

#### 2. Login

**Endpoint:** `POST /api/auth/login`

**Headers:**
```
Content-Type: application/json
Accept: application/json
```

**Body:**
```json
{
    "email": "joao@exemplo.com",
    "password": "password123"
}
```

**Resposta de Sucesso (200):**
```json
{
    "status": "sucesso",
    "mensagem": "Login efetuado com sucesso",
    "utilizador": {
        "id": 1,
        "name": "João Silva",
        "email": "joao@exemplo.com"
    },
    "autorizacao": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "tipo": "bearer",
        "expira_em": 3600
    }
}
```

**Resposta de Erro (401):**
```json
{
    "status": "erro",
    "mensagem": "Credenciais inválidas. Verifique o seu email e palavra-passe."
}
```

---

#### 3. Logout

**Endpoint:** `POST /api/auth/logout`

**Headers:**
```
Authorization: Bearer {token}
Accept: application/json
```

**Resposta de Sucesso (200):**
```json
{
    "status": "sucesso",
    "mensagem": "Sessão terminada com sucesso"
}
```

---

#### 4. Refresh Token

**Endpoint:** `POST /api/auth/refresh`

**Headers:**
```
Authorization: Bearer {token}
Accept: application/json
```

**Resposta de Sucesso (200):**
```json
{
    "status": "sucesso",
    "mensagem": "Token atualizado com sucesso",
    "autorizacao": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "tipo": "bearer",
        "expira_em": 3600
    }
}
```

---

#### 5. Obter Dados do Utilizador

**Endpoint:** `GET /api/auth/me`

**Headers:**
```
Authorization: Bearer {token}
Accept: application/json
```

**Resposta de Sucesso (200):**
```json
{
    "status": "sucesso",
    "utilizador": {
        "id": 1,
        "name": "João Silva",
        "email": "joao@exemplo.com",
        "email_verified_at": null,
        "created_at": "2024-01-15T10:30:00.000000Z",
        "updated_at": "2024-01-15T10:30:00.000000Z"
    }
}
```

---

#### 6. Atualizar Perfil

**Endpoint:** `PUT /api/auth/profile`

**Headers:**
```
Authorization: Bearer {token}
Content-Type: application/json
Accept: application/json
```

**Body:**
```json
{
    "name": "João Silva Atualizado",
    "email": "joao.novo@exemplo.com"
}
```

**Resposta de Sucesso (200):**
```json
{
    "status": "sucesso",
    "mensagem": "Perfil atualizado com sucesso",
    "utilizador": {
        "id": 1,
        "name": "João Silva Atualizado",
        "email": "joao.novo@exemplo.com"
    }
}
```

---

#### 7. Alterar Palavra-passe

**Endpoint:** `PUT /api/auth/change-password`

**Headers:**
```
Authorization: Bearer {token}
Content-Type: application/json
Accept: application/json
```

**Body:**
```json
{
    "current_password": "password123",
    "password": "novapassword456",
    "password_confirmation": "novapassword456"
}
```

**Resposta de Sucesso (200):**
```json
{
    "status": "sucesso",
    "mensagem": "Palavra-passe alterada com sucesso"
}
```

---

## Exemplos de Utilização

### Fluxo Típico de Autenticação

```
┌─────────────────┐         ┌─────────────────┐
│     Cliente     │         │     Servidor    │
└────────┬────────┘         └────────┬────────┘
         │                           │
         │  1. POST /api/auth/login  │
         │  {email, password}        │
         │ ─────────────────────────>│
         │                           │
         │  2. Validar credenciais   │
         │                           │
         │  3. Retorna JWT Token     │
         │ <─────────────────────────│
         │                           │
         │  4. GET /api/auth/me      │
         │  Header: Bearer {token}   │
         │ ─────────────────────────>│
         │                           │
         │  5. Validar token         │
         │                           │
         │  6. Retorna dados user    │
         │ <─────────────────────────│
         │                           │
```

### Guardar o Token no Cliente

#### JavaScript (LocalStorage)

```javascript
// Após login bem-sucedido
function handleLogin(response) {
    // Guardar o token
    localStorage.setItem('jwt_token', response.autorizacao.token);
    
    // Redirecionar para área protegida
    window.location.href = '/dashboard';
}

// Fazer pedidos autenticados
async function fetchProtectedData() {
    const token = localStorage.getItem('jwt_token');
    
    const response = await fetch('/api/auth/me', {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json'
        }
    });
    
    if (response.status === 401) {
        // Token expirado, tentar refresh ou redirecionar para login
        handleTokenExpired();
    }
    
    return response.json();
}

// Logout
function handleLogout() {
    localStorage.removeItem('jwt_token');
    window.location.href = '/login';
}
```

#### Axios (Interceptor)

```javascript
import axios from 'axios';

// Configurar o interceptor para adicionar o token automaticamente
axios.interceptors.request.use(config => {
    const token = localStorage.getItem('jwt_token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// Interceptor para lidar com erros de autenticação
axios.interceptors.response.use(
    response => response,
    error => {
        if (error.response.status === 401) {
            // Token inválido ou expirado
            localStorage.removeItem('jwt_token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);
```

---

## Testar com cURL

### Iniciar o servidor Laravel

```bash
php artisan serve
```

O servidor estará disponível em `http://localhost:8000`.

### 1. Registar um utilizador

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "name": "João Silva",
    "email": "joao@exemplo.com",
    "password": "password123",
    "password_confirmation": "password123"
  }'
```

### 2. Fazer login

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "email": "joao@exemplo.com",
    "password": "password123"
  }'
```

Guarda o token retornado para os próximos pedidos.

### 3. Obter dados do utilizador (autenticado)

```bash
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer AQUI_O_TEU_TOKEN" \
  -H "Accept: application/json"
```

### 4. Atualizar perfil

```bash
curl -X PUT http://localhost:8000/api/auth/profile \
  -H "Authorization: Bearer AQUI_O_TEU_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "name": "João Silva Atualizado"
  }'
```

### 5. Alterar palavra-passe

```bash
curl -X PUT http://localhost:8000/api/auth/change-password \
  -H "Authorization: Bearer AQUI_O_TEU_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "current_password": "password123",
    "password": "novapassword456",
    "password_confirmation": "novapassword456"
  }'
```

### 6. Refresh do token

```bash
curl -X POST http://localhost:8000/api/auth/refresh \
  -H "Authorization: Bearer AQUI_O_TEU_TOKEN" \
  -H "Accept: application/json"
```

### 7. Logout

```bash
curl -X POST http://localhost:8000/api/auth/logout \
  -H "Authorization: Bearer AQUI_O_TEU_TOKEN" \
  -H "Accept: application/json"
```

---

## Testar com Postman

### Configuração Inicial

1. **Criar uma nova Collection** chamada "JWT Auth Laravel"

2. **Configurar variáveis de ambiente:**
   - `base_url`: `http://localhost:8000`
   - `token`: (deixar vazio, será preenchido automaticamente)

### Configurar o Token Automático

No separador **Tests** do pedido de Login, adiciona:

```javascript
if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("token", jsonData.autorizacao.token);
}
```

### Headers para Rotas Protegidas

Para rotas que requerem autenticação, adiciona o header:

```
Authorization: Bearer {{token}}
```

### Exemplo de Collection

```
📁 JWT Auth Laravel
├── 📄 Register
│   └── POST {{base_url}}/api/auth/register
├── 📄 Login
│   └── POST {{base_url}}/api/auth/login
├── 📄 Me
│   └── GET {{base_url}}/api/auth/me
├── 📄 Update Profile
│   └── PUT {{base_url}}/api/auth/profile
├── 📄 Change Password
│   └── PUT {{base_url}}/api/auth/change-password
├── 📄 Refresh Token
│   └── POST {{base_url}}/api/auth/refresh
└── 📄 Logout
    └── POST {{base_url}}/api/auth/logout
```

---

## Boas Práticas de Segurança

### 1. Proteger a Chave Secreta

- **Nunca** colocar a chave `JWT_SECRET` no controlo de versões
- Usar chaves diferentes para cada ambiente (development, staging, production)
- Regenerar a chave periodicamente

```bash
# Regenerar a chave
php artisan jwt:secret --force
```

### 2. Definir Tempo de Expiração Adequado

No ficheiro `.env`:

```env
# Token expira em 60 minutos
JWT_TTL=60

# Refresh disponível durante 2 semanas
JWT_REFRESH_TTL=20160
```

### 3. Usar HTTPS em Produção

Os tokens JWT são enviados em texto claro no header. Usa sempre HTTPS para encriptar a comunicação.

### 4. Validar Input

Sempre validar os dados recebidos:

```php
$validator = Validator::make($request->all(), [
    'email' => 'required|email|max:255',
    'password' => 'required|min:6',
]);
```

### 5. Não Guardar Dados Sensíveis no Payload

O payload do JWT pode ser descodificado facilmente. Não incluas:
- Palavras-passe
- Números de cartão de crédito
- Informação pessoal sensível

### 6. Implementar Blacklist de Tokens

O pacote jwt-auth suporta blacklist de tokens invalidados:

```php
// config/jwt.php
'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),
```

### 7. Limitar Tentativas de Login

```php
// No método login
if (RateLimiter::tooManyAttempts($this->throttleKey($request), 5)) {
    return response()->json([
        'status' => 'erro',
        'mensagem' => 'Demasiadas tentativas. Tenta novamente em X segundos.'
    ], 429);
}
```

---

## Resolução de Problemas

### Problema: Token não é aceite

**Possíveis causas:**
1. Token expirado
2. Token malformado
3. Chave secreta diferente

**Solução:**
```bash
# Verificar se a chave está definida
php artisan config:show jwt.secret

# Limpar cache
php artisan config:clear
php artisan cache:clear
```

### Problema: "Unauthenticated" em rotas protegidas

**Verificar:**
1. Header `Authorization` está presente?
2. Formato correto: `Bearer {token}`?
3. Token não está expirado?

```bash
# Testar token
php artisan tinker
>>> JWTAuth::parseToken()->authenticate()
```

### Problema: CORS errors no browser

Instalar e configurar o pacote de CORS:

```php
// config/cors.php
'paths' => ['api/*'],
'allowed_origins' => ['http://localhost:3000'],
'allowed_headers' => ['*'],
'exposed_headers' => ['Authorization'],
```

### Problema: Token expira muito rápido

Aumentar o TTL no `.env`:

```env
JWT_TTL=1440  # 24 horas em minutos
```

---

## Recursos Adicionais

### Documentação Oficial

- [JWT.io](https://jwt.io/) - Debugger de JWT
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - Especificação JWT
- [tymon/jwt-auth Documentation](https://jwt-auth.readthedocs.io/)
- [Laravel Documentation](https://laravel.com/docs)

### Ferramentas Úteis

- **Postman** - Cliente API para testar endpoints
- **JWT.io Debugger** - Descodificar e verificar tokens
- **Insomnia** - Alternativa ao Postman

### Próximos Passos

1. **Implementar verificação de email**
2. **Adicionar autenticação OAuth** (Google, Facebook)
3. **Implementar 2FA** (Two-Factor Authentication)
4. **Criar middleware personalizado** para permissões/roles

---

## Estrutura de Ficheiros do Projeto

```
autenticacao/
├── app/
│   ├── Http/
│   │   └── Controllers/
│   │       └── AuthController.php    # Controlador de autenticação
│   └── Models/
│       └── User.php                  # Modelo com JWTSubject
├── config/
│   ├── auth.php                      # Configuração de guards
│   └── jwt.php                       # Configuração JWT
├── routes/
│   ├── api.php                       # Rotas da API
│   └── web.php                       # Rotas web
├── .env                              # Variáveis de ambiente (JWT_SECRET)
└── README.md                         # Este ficheiro
```

---

## Autor

Exemplo preparado para a disciplina de Desenvolvimento Web.

## Licença

Este projeto é disponibilizado para fins educacionais.
