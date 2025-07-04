import os
from app import create_app

# Criar a aplicação
app = create_app()

if __name__ == '__main__':
    # Configurações para desenvolvimento
    host = '0.0.0.0'  # Permite acesso externo
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"🚀 Iniciando servidor de autenticação...")
    print(f"📍 Endereço: http://{host}:{port}")
    print(f"🔧 Modo debug: {debug}")
    print(f"📋 Endpoints disponíveis:")
    print(f"   GET  /health - Health check")
    print(f"   GET  /api/auth/status - Status da API")
    print(f"   POST /api/auth/register - Registrar usuário")
    print(f"   POST /api/auth/login - Login")
    print(f"   GET  /api/auth/validate - Validar token")
    print(f"   POST /api/auth/logout - Logout")
    print(f"   GET  /api/auth/user/info - Info do usuário")
    print(f"   POST /api/auth/user/extend-subscription - Estender assinatura")
    
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )

