from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from typing import Dict, Any
from app.services.auth_service import AuthService
from app.utils.jwt_handler import JWTHandler

auth_bp = Blueprint('auth', __name__)

def require_auth(f):
    """Decorator para rotas que requerem autenticação"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Token de autorização necessário'}), 401
        
        token = JWTHandler.extract_token_from_header(auth_header)
        if not token:
            return jsonify({'error': 'Formato de token inválido'}), 401
        
        auth_service = AuthService()
        success, result = auth_service.validate_token(token)
        
        if not success:
            return jsonify(result), 401
        
        # Adicionar dados do usuário ao request
        request.current_user = result['user']
        request.token_info = result['token_info']
        
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Registra um novo usuário
    
    Body:
    {
        "name": "STRING",
        "surname": "STRING",
        "email": "STRING",
        "password": "STRING"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Dados JSON necessários'}), 400
        
        name = data.get('name', '').strip()
        surname = data.get('surname', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        auth_service = AuthService()

        success, result = auth_service.register_user_in_supabase(
            email=email,
            password=password
        )

        auth_service.register_user(
            user_id=result['user']['id'],
            name=name,
            surname=surname,
            email=email,
            password=password
        )

        if success:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        print("Erro no /register:", str(e))
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Realiza login do usuário
    
    Body:
    {
        "email": "string",
        "password": "string"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON Data necessary'}), 400
        
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        auth_service = AuthService()
        success, result = auth_service.login(email, password)
        
        if success:
            return jsonify(result), 200
        else:
            #if result.get('code') == 'SUBSCRIPTION_EXPIRED':
                #return jsonify(result), 402
            #else:
                return jsonify(result), 401
                
    except Exception as e:
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/validate', methods=['GET'])
@require_auth
def validate():
    """
    Valida o token atual
    
    Headers:
    Authorization: Bearer <token>
    """
    try:
        return jsonify({
            'valid': True,
            'message': 'Token válido',
            'user': request.current_user,
            'token_info': request.token_info
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    """
    Realiza logout revogando o token
    
    Headers:
    Authorization: Bearer <token>
    """
    try:
        auth_header = request.headers.get('Authorization')
        token = JWTHandler.extract_token_from_header(auth_header)
        
        auth_service = AuthService()
        success, result = auth_service.logout(token)
        
        if success:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/user/info', methods=['GET'])
@require_auth
def get_user_info():
    """
    Obtém informações do usuário atual
    
    Headers:
    Authorization: Bearer <token>
    """
    try:
        user_id = request.current_user['id']
        
        auth_service = AuthService()
        success, result = auth_service.get_user_info(user_id)
        
        if success:
            return jsonify(result), 200
        else:
            return jsonify(result), 404
            
    except Exception as e:
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/user/extend-subscription', methods=['POST'])
@require_auth
def extend_subscription():
    """
    Estende a assinatura do usuário
    
    Headers:
    Authorization: Bearer <token>
    
    Body:
    {
        "months": 1
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Dados JSON necessários'}), 400
        
        months = data.get('months', 1)
        if not isinstance(months, int) or months <= 0:
            return jsonify({'error': 'Número de meses deve ser um inteiro positivo'}), 400
        
        user_id = request.current_user['id']
        
        auth_service = AuthService()
        success, result = auth_service.extend_subscription(user_id, months)
        
        if success:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/admin/cleanup-tokens', methods=['POST'])
def cleanup_expired_tokens():
    """
    Remove tokens expirados (rota administrativa)
    
    Headers:
    X-Admin-Key: <admin_key>
    """
    try:
        admin_key = request.headers.get('X-Admin-Key')
        expected_key = current_app.config.get('ADMIN_KEY', 'admin-key-123')
        
        if admin_key != expected_key:
            return jsonify({'error': 'Chave administrativa inválida'}), 403
        
        auth_service = AuthService()
        removed_count = auth_service.cleanup_expired_tokens()
        
        return jsonify({
            'message': f'{removed_count} tokens expirados removidos',
            'removed_count': removed_count
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Erro interno do servidor'}), 500

@auth_bp.route('/status', methods=['GET'])
def status():
    """
    Verifica o status da API
    """
    return jsonify({
        'status': 'online',
        'service': 'Auth API',
        'version': '1.0.0',
        'endpoints': {
            'POST /register': 'Registrar novo usuário',
            'POST /login': 'Fazer login',
            'GET /validate': 'Validar token',
            'POST /logout': 'Fazer logout',
            'GET /user/info': 'Informações do usuário',
            'POST /user/extend-subscription': 'Estender assinatura'
        }
    }), 200

# Tratamento de erros
@auth_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint não encontrado'}), 404

@auth_bp.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Método não permitido'}), 405

@auth_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Erro interno do servidor'}), 500

