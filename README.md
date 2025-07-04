# Sistema de Autenticação por Assinatura

Um sistema backend profissional e escalável para autenticação baseada em assinatura mensal, desenvolvido com Flask e JWT.

## 📋 Índice

- [Visão Geral](#visão-geral)
- [Características](#características)
- [Arquitetura](#arquitetura)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso da API](#uso-da-api)
- [Endpoints](#endpoints)
- [Exemplos de Uso](#exemplos-de-uso)
- [Segurança](#segurança)
- [Deployment](#deployment)
- [Testes](#testes)
- [Troubleshooting](#troubleshooting)

## 🎯 Visão Geral

Este sistema foi desenvolvido para aplicações desktop que necessitam de validação de usuários baseada em assinatura mensal. O backend fornece uma API REST completa para:

- Registro e autenticação de usuários
- Controle de assinatura mensal com período de tolerância
- Geração e validação de tokens JWT
- Gestão de sessões ativas
- Extensão de assinaturas

## ✨ Características

### Funcionalidades Principais

- **Autenticação JWT**: Tokens seguros com expiração configurável
- **Controle de Assinatura**: Validação automática de assinatura mensal
- **Período de Tolerância**: 3 dias de graça após vencimento (configurável)
- **Gestão de Sessões**: Controle de tokens ativos e revogação
- **API RESTful**: Endpoints padronizados e documentados
- **CORS Habilitado**: Suporte para aplicações frontend
- **Banco SQLite**: Leve e eficiente para início

### Características Técnicas

- **Framework**: Flask 3.1.1
- **Autenticação**: PyJWT 2.10.1
- **Banco de Dados**: SQLite3
- **CORS**: Flask-CORS 6.0.1
- **Arquitetura**: Modular e escalável
- **Testes**: Suite completa de testes automatizados

## 🏗️ Arquitetura

### Estrutura do Projeto

```
auth-server/
├── app/
│   ├── __init__.py            # Factory da aplicação Flask
│   ├── config.py              # Configurações do sistema
│   ├── models.py              # Modelos de dados (User, Token)
│   ├── routes/
│   │   ├── __init__.py
│   │   └── auth_routes.py     # Rotas da API de autenticação
│   ├── services/
│   │   ├── __init__.py
│   │   └── auth_service.py    # Lógica de negócio
│   └── utils/
│       ├── __init__.py
│       └── jwt_handler.py     # Manipulação de tokens JWT
├── database/
│   └── users.db               # Banco de dados SQLite
├── run.py                     # Arquivo principal do servidor
├── test_api.py                # Testes automatizados
├── requirements.txt           # Dependências Python
└── README.md                  # Esta documentação
```

### Componentes

#### 1. Models (`app/models.py`)
- **DatabaseManager**: Gerencia conexões e criação de tabelas
- **User**: Operações relacionadas a usuários (CRUD, autenticação, assinatura)
- **Token**: Gestão de tokens ativos (armazenamento, validação, revogação)

#### 2. Services (`app/services/auth_service.py`)
- **AuthService**: Lógica de negócio principal
  - Registro de usuários
  - Login e logout
  - Validação de tokens
  - Controle de assinatura
  - Extensão de assinatura

#### 3. Utils (`app/utils/jwt_handler.py`)
- **JWTHandler**: Manipulação de tokens JWT
  - Geração de tokens
  - Decodificação e validação
  - Extração de headers

#### 4. Routes (`app/routes/auth_routes.py`)
- **Blueprint auth_bp**: Endpoints da API
- **Decorator require_auth**: Middleware de autenticação

## 🚀 Instalação

### Pré-requisitos

- Python 3.11+
- pip (gerenciador de pacotes Python)

### Passos de Instalação

1. **Clone ou baixe o projeto**
```bash
# Se usando git
git clone <repository-url>
cd auth-server

# Ou extraia o arquivo ZIP fornecido
unzip code-helper-server.zip
cd auth-server
```

2. **Instale as dependências**
```bash
pip install -r requirements.txt
```

3. **Execute o servidor**
```bash
python3 run.py
```

O servidor estará disponível em `http://localhost:5000`

## ⚙️ Configuração

### Variáveis de Ambiente

O sistema suporta configuração via variáveis de ambiente:

```bash
# Ambiente de execução (development, production, testing)
export FLASK_ENV=development

# Chaves secretas (OBRIGATÓRIO em produção)
export SECRET_KEY=sua-chave-secreta-super-segura
export JWT_SECRET_KEY=jwt-chave-secreta-super-segura

# Porta do servidor
export PORT=5000

# Chave administrativa para limpeza de tokens
export ADMIN_KEY=admin-key-123
```

### Configurações Disponíveis

No arquivo `app/config.py`:

- **JWT_ACCESS_TOKEN_EXPIRES**: Tempo de expiração dos tokens (padrão: 24 horas)
- **SUBSCRIPTION_GRACE_DAYS**: Dias de tolerância após vencimento (padrão: 3 dias)
- **DATABASE_PATH**: Caminho do banco de dados SQLite
- **CORS_ORIGINS**: Origens permitidas para CORS (padrão: "*")

## 📡 Uso da API

### Base URL
```
http://localhost:5000/api/auth
```

### Autenticação
A maioria dos endpoints requer autenticação via token JWT no header:
```
Authorization: Bearer <seu-token-jwt>
```

### Formato de Resposta
Todas as respostas são em JSON:

**Sucesso:**
```json
{
  "message": "Operação realizada com sucesso",
  "data": { ... }
}
```

**Erro:**
```json
{
  "error": "Descrição do erro"
}
```

## 🛠️ Endpoints

### 1. Status da API
```http
GET /api/auth/status
```

**Resposta:**
```json
{
  "status": "online",
  "service": "Auth API",
  "version": "1.0.0",
  "endpoints": { ... }
}
```

### 2. Registrar Usuário
```http
POST /api/auth/register
```

**Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "subscription_months": 1
}
```

**Resposta (201):**
```json
{
  "message": "Usuário criado com sucesso",
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "subscription_end_date": "2025-08-02T10:58:58.331517",
    "is_active": true
  }
}
```

### 3. Login
```http
POST /api/auth/login
```

**Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Resposta (200):**
```json
{
  "message": "Login realizado com sucesso",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 86400,
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "subscription_end": "2025-08-02T10:58:58.331517"
  }
}
```

**Erro de Assinatura Expirada (402):**
```json
{
  "error": "Assinatura expirada",
  "code": "SUBSCRIPTION_EXPIRED",
  "subscription_end": "2025-07-01T10:58:58.331517"
}
```

### 4. Validar Token
```http
GET /api/auth/validate
Authorization: Bearer <token>
```

**Resposta (200):**
```json
{
  "valid": true,
  "message": "Token válido",
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "subscription_end": "2025-08-02T10:58:58.331517"
  },
  "token_info": {
    "token_id": "4f94e02f-c9e7-4314-a423-c94e364bc07b",
    "issued_at": 1751554738,
    "expires_at": 1751641138
  }
}
```

### 5. Logout
```http
POST /api/auth/logout
Authorization: Bearer <token>
```

**Resposta (200):**
```json
{
  "message": "Logout realizado com sucesso"
}
```

### 6. Informações do Usuário
```http
GET /api/auth/user/info
Authorization: Bearer <token>
```

**Resposta (200):**
```json
{
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "is_active": 1,
    "subscription_end_date": "2025-08-02T10:58:58.331517"
  },
  "subscription_valid": true
}
```

### 7. Estender Assinatura
```http
POST /api/auth/user/extend-subscription
Authorization: Bearer <token>
```

**Body:**
```json
{
  "months": 2
}
```

**Resposta (200):**
```json
{
  "message": "Assinatura estendida por 2 meses",
  "new_subscription_end": "2025-10-01T10:58:58.331517"
}
```

### 8. Limpeza de Tokens (Admin)
```http
POST /api/auth/admin/cleanup-tokens
X-Admin-Key: <admin-key>
```

**Resposta (200):**
```json
{
  "message": "5 tokens expirados removidos",
  "removed_count": 5
}
```

## 💡 Exemplos de Uso

### Exemplo em Python (Cliente Desktop)

```python
import requests
import json

class AuthClient:
    def __init__(self, base_url="http://localhost:5000/api/auth"):
        self.base_url = base_url
        self.token = None
    
    def login(self, username, password):
        """Realiza login e armazena o token"""
        response = requests.post(f"{self.base_url}/login", json={
            "username": username,
            "password": password
        })
        
        if response.status_code == 200:
            data = response.json()
            self.token = data["token"]
            return True, data
        elif response.status_code == 402:
            # Assinatura expirada
            return False, response.json()
        else:
            return False, response.json()
    
    def validate_access(self):
        """Valida se o usuário pode usar a aplicação"""
        if not self.token:
            return False, {"error": "Não logado"}
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{self.base_url}/validate", headers=headers)
        
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, response.json()
    
    def logout(self):
        """Realiza logout"""
        if not self.token:
            return True, {"message": "Já deslogado"}
        
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(f"{self.base_url}/logout", headers=headers)
        
        self.token = None
        return response.status_code == 200, response.json()

# Uso na aplicação desktop
auth = AuthClient()

# Login
success, result = auth.login("meuusuario", "minhasenha")
if success:
    print("Login realizado com sucesso!")
    
    # Validar acesso antes de usar funcionalidades
    valid, info = auth.validate_access()
    if valid:
        print("Usuário autorizado a usar a aplicação")
        # Continuar com a aplicação...
    else:
        print(f"Acesso negado: {info['error']}")
        # Mostrar tela de renovação de assinatura
else:
    if result.get('code') == 'SUBSCRIPTION_EXPIRED':
        print("Assinatura expirada! Renove para continuar usando.")
    else:
        print(f"Erro no login: {result['error']}")
```

### Exemplo em JavaScript (Frontend Web)

```javascript
class AuthAPI {
    constructor(baseURL = 'http://localhost:5000/api/auth') {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('auth_token');
    }
    
    async login(username, password) {
        try {
            const response = await fetch(`${this.baseURL}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.token = data.token;
                localStorage.setItem('auth_token', this.token);
                return { success: true, data };
            } else {
                return { success: false, error: data };
            }
        } catch (error) {
            return { success: false, error: { message: 'Erro de conexão' } };
        }
    }
    
    async validateToken() {
        if (!this.token) return { success: false, error: 'No token' };
        
        try {
            const response = await fetch(`${this.baseURL}/validate`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            const data = await response.json();
            return { success: response.ok, data };
        } catch (error) {
            return { success: false, error: { message: 'Erro de conexão' } };
        }
    }
    
    async logout() {
        if (!this.token) return { success: true };
        
        try {
            await fetch(`${this.baseURL}/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
        } catch (error) {
            // Ignorar erros de logout
        }
        
        this.token = null;
        localStorage.removeItem('auth_token');
        return { success: true };
    }
}

// Uso
const auth = new AuthAPI();

// Verificar se já está logado
auth.validateToken().then(result => {
    if (result.success) {
        console.log('Usuário já logado:', result.data.user);
    } else {
        console.log('Necessário fazer login');
    }
});
```

## 🔒 Segurança

### Medidas Implementadas

1. **Hash de Senhas**: Senhas são hasheadas com SHA-256
2. **Tokens JWT**: Assinados com chave secreta
3. **Expiração de Tokens**: Tokens têm tempo de vida limitado
4. **Revogação de Tokens**: Tokens podem ser revogados no logout
5. **Validação de Assinatura**: Verificação contínua de assinatura válida
6. **CORS Configurado**: Controle de origens permitidas

### Recomendações de Produção

1. **Use HTTPS**: Sempre em produção
2. **Chaves Secretas Fortes**: Use geradores de chaves seguras
3. **Variáveis de Ambiente**: Nunca hardcode chaves no código
4. **Banco de Dados Seguro**: Migre para PostgreSQL em produção
5. **Rate Limiting**: Implemente limitação de tentativas
6. **Logs de Auditoria**: Registre tentativas de login
7. **Backup Regular**: Faça backup do banco de dados

### Exemplo de Configuração Segura

```bash
# Gerar chaves seguras
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Configurar ambiente de produção
export FLASK_ENV=production
export CORS_ORIGINS=https://meudominio.com
```

## 🚀 Deployment

### Desenvolvimento Local
```bash
python3 run.py
```

### Produção com Gunicorn
```bash
# Instalar Gunicorn
pip install gunicorn

# Executar
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
```

### Docker
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:create_app()"]
```

### Nginx (Proxy Reverso)
```nginx
server {
    listen 80;
    server_name meudominio.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🧪 Testes

### Executar Testes
```bash
python3 test_api.py
```

### Testes Incluídos

1. **Status da API**: Verifica se o servidor está respondendo
2. **Registro de Usuário**: Testa criação de novos usuários
3. **Login**: Verifica autenticação e geração de tokens
4. **Validação de Token**: Testa validação de tokens JWT
5. **Informações do Usuário**: Verifica recuperação de dados
6. **Extensão de Assinatura**: Testa renovação de assinatura
7. **Logout**: Verifica revogação de tokens
8. **Casos de Erro**: Testa tratamento de erros

### Exemplo de Saída dos Testes
```
🧪 Iniciando testes da API de autenticação...

1️⃣ Testando status da API...
   Status: 200
   ✅ Status OK

2️⃣ Testando registro de usuário...
   Status: 201
   ✅ Registro OK

3️⃣ Testando login...
   Status: 200
   ✅ Login OK

...

🎉 Todos os testes passaram com sucesso!
```

## 🔧 Troubleshooting

### Problemas Comuns

#### 1. Erro "ModuleNotFoundError"
```bash
# Instalar dependências
pip install -r requirements.txt
```

#### 2. Erro "Permission denied" no banco
```bash
# Verificar permissões do diretório
chmod 755 database/
chmod 644 database/users.db
```

#### 3. Erro de CORS
```python
# Verificar configuração no config.py
CORS_ORIGINS = "*"  # Para desenvolvimento
CORS_ORIGINS = "https://meudominio.com"  # Para produção
```

#### 4. Token sempre inválido
```bash
# Verificar se as chaves secretas são consistentes
echo $JWT_SECRET_KEY
```

#### 5. Assinatura sempre expirada
```python
# Verificar configuração de tolerância
SUBSCRIPTION_GRACE_DAYS = 3  # Dias de tolerância
```

### Logs de Debug

Para habilitar logs detalhados:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Verificação de Saúde

```bash
# Verificar se o servidor está rodando
curl http://localhost:5000/health

# Verificar status da API
curl http://localhost:5000/api/auth/status
```

## 📞 Suporte

Para suporte técnico ou dúvidas sobre implementação:

1. Verifique esta documentação
2. Execute os testes automatizados
3. Consulte os logs de erro
4. Verifique as configurações de ambiente

---

**Desenvolvido por Manus AI** - Sistema de Autenticação por Assinatura v1.0.0

