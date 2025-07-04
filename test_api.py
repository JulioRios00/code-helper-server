#!/usr/bin/env python3
"""
Script de teste para a API de autenticação
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000/api/auth"

def test_api():
    """Executa testes básicos da API"""
    print("🧪 Iniciando testes da API de autenticação...\n")
    
    # 1. Teste de status
    print("1️⃣ Testando status da API...")
    try:
        response = requests.get(f"{BASE_URL}/status")
        print(f"   Status: {response.status_code}")
        print(f"   Resposta: {response.json()}")
        assert response.status_code == 200
        print("   ✅ Status OK\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de status: {e}\n")
        return False
    
    # 2. Teste de registro
    print("2️⃣ Testando registro de usuário...")
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "123456",
        "subscription_months": 1
    }
    
    try:
        response = requests.post(f"{BASE_URL}/register", json=user_data)
        print(f"   Status: {response.status_code}")
        print(f"   Resposta: {response.json()}")
        assert response.status_code == 201
        print("   ✅ Registro OK\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de registro: {e}\n")
        return False
    
    # 3. Teste de login
    print("3️⃣ Testando login...")
    login_data = {
        "username": "testuser",
        "password": "123456"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login", json=login_data)
        print(f"   Status: {response.status_code}")
        result = response.json()
        print(f"   Resposta: {result}")
        assert response.status_code == 200
        assert "token" in result
        
        token = result["token"]
        print("   ✅ Login OK\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de login: {e}\n")
        return False
    
    # 4. Teste de validação de token
    print("4️⃣ Testando validação de token...")
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{BASE_URL}/validate", headers=headers)
        print(f"   Status: {response.status_code}")
        print(f"   Resposta: {response.json()}")
        assert response.status_code == 200
        print("   ✅ Validação OK\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de validação: {e}\n")
        return False
    
    # 5. Teste de informações do usuário
    print("5️⃣ Testando informações do usuário...")
    try:
        response = requests.get(f"{BASE_URL}/user/info", headers=headers)
        print(f"   Status: {response.status_code}")
        print(f"   Resposta: {response.json()}")
        assert response.status_code == 200
        print("   ✅ Info do usuário OK\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de info do usuário: {e}\n")
        return False
    
    # 6. Teste de extensão de assinatura
    print("6️⃣ Testando extensão de assinatura...")
    extend_data = {"months": 2}
    
    try:
        response = requests.post(f"{BASE_URL}/user/extend-subscription", 
                               json=extend_data, headers=headers)
        print(f"   Status: {response.status_code}")
        print(f"   Resposta: {response.json()}")
        assert response.status_code == 200
        print("   ✅ Extensão de assinatura OK\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de extensão: {e}\n")
        return False
    
    # 7. Teste de logout
    print("7️⃣ Testando logout...")
    try:
        response = requests.post(f"{BASE_URL}/logout", headers=headers)
        print(f"   Status: {response.status_code}")
        print(f"   Resposta: {response.json()}")
        assert response.status_code == 200
        print("   ✅ Logout OK\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de logout: {e}\n")
        return False
    
    # 8. Teste de token inválido após logout
    print("8️⃣ Testando token inválido após logout...")
    try:
        response = requests.get(f"{BASE_URL}/validate", headers=headers)
        print(f"   Status: {response.status_code}")
        print(f"   Resposta: {response.json()}")
        assert response.status_code == 401
        print("   ✅ Token invalidado corretamente\n")
    except Exception as e:
        print(f"   ❌ Erro no teste de token inválido: {e}\n")
        return False
    
    print("🎉 Todos os testes passaram com sucesso!")
    return True

def test_error_cases():
    """Testa casos de erro"""
    print("\n🔍 Testando casos de erro...\n")
    
    # Teste de login com credenciais inválidas
    print("1️⃣ Testando login com credenciais inválidas...")
    try:
        response = requests.post(f"{BASE_URL}/login", json={
            "username": "invalid",
            "password": "wrong"
        })
        print(f"   Status: {response.status_code}")
        assert response.status_code == 401
        print("   ✅ Erro de credenciais tratado corretamente\n")
    except Exception as e:
        print(f"   ❌ Erro no teste: {e}\n")
    
    # Teste de acesso sem token
    print("2️⃣ Testando acesso sem token...")
    try:
        response = requests.get(f"{BASE_URL}/validate")
        print(f"   Status: {response.status_code}")
        assert response.status_code == 401
        print("   ✅ Acesso negado corretamente\n")
    except Exception as e:
        print(f"   ❌ Erro no teste: {e}\n")

if __name__ == "__main__":
    # Aguardar servidor inicializar
    print("⏳ Aguardando servidor inicializar...")
    time.sleep(2)
    
    # Executar testes
    success = test_api()
    test_error_cases()
    
    if success:
        print("\n✅ Sistema de autenticação funcionando corretamente!")
    else:
        print("\n❌ Alguns testes falharam.")

