from typing import Dict, Any, Optional, Tuple
from flask import current_app
from datetime import datetime

from app.models import DatabaseManager, User, Token
from app.utils.jwt_handler import JWTHandler

class AuthService:
    """Serviço principal de autenticação"""
    
    def __init__(self):
        self.db_manager = DatabaseManager(current_app.config['DATABASE_PATH'])
        self.user_model = User(self.db_manager)
        self.token_model = Token(self.db_manager)
        self.jwt_handler = JWTHandler()
    
    def register_user(self, username: str, email: str, password: str, 
                     subscription_months: int = 1) -> Tuple[bool, Dict[str, Any]]:
        """
        Registra um novo usuário
        
        Args:
            username: Nome de usuário
            email: Email do usuário
            password: Senha do usuário
            subscription_months: Meses de assinatura inicial
            
        Returns:
            Tupla (sucesso, dados/erro)
        """
        try:
            # Validações básicas
            if not username or len(username) < 3:
                return False, {'error': 'Nome de usuário deve ter pelo menos 3 caracteres'}
            
            if not email or '@' not in email:
                return False, {'error': 'Email inválido'}
            
            if not password or len(password) < 6:
                return False, {'error': 'Senha deve ter pelo menos 6 caracteres'}
            
            # Criar usuário
            user_data = self.user_model.create_user(
                username=username,
                email=email,
                password=password,
                subscription_months=subscription_months
            )
            
            return True, {
                'message': 'Usuário criado com sucesso',
                'user': user_data
            }
            
        except ValueError as e:
            return False, {'error': str(e)}
        except Exception as e:
            return False, {'error': 'Erro interno do servidor'}
    
    def login(self, username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Realiza login do usuário
        
        Args:
            username: Nome de usuário
            password: Senha
            
        Returns:
            Tupla (sucesso, dados/erro)
        """
        try:
            # Autenticar usuário
            user_data = self.user_model.authenticate(username, password)
            if not user_data:
                return False, {'error': 'Credenciais inválidas'}
            
            # Verificar se a assinatura está válida
            grace_days = current_app.config.get('SUBSCRIPTION_GRACE_DAYS', 3)
            if not self.user_model.is_subscription_valid(user_data['id'], grace_days):
                return False, {
                    'error': 'Assinatura expirada',
                    'code': 'SUBSCRIPTION_EXPIRED',
                    'subscription_end': user_data['subscription_end_date']
                }
            
            # Gerar token JWT
            token_data = self.jwt_handler.generate_token(user_data)
            
            # Armazenar token no banco
            self.token_model.store_token(
                user_id=user_data['id'],
                token_id=token_data['token_id'],
                expires_at=token_data['expires_at']
            )
            
            return True, {
                'message': 'Login realizado com sucesso',
                'token': token_data['token'],
                'expires_in': token_data['expires_in'],
                'user': {
                    'id': user_data['id'],
                    'username': user_data['username'],
                    'email': user_data['email'],
                    'subscription_end': user_data['subscription_end_date']
                }
            }
            
        except Exception as e:
            return False, {'error': 'Erro interno do servidor'}
    
    def validate_token(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Valida um token JWT
        
        Args:
            token: Token JWT para validar
            
        Returns:
            Tupla (sucesso, dados/erro)
        """
        try:
            # Decodificar token
            payload = self.jwt_handler.decode_token(token)
            if not payload:
                return False, {'error': 'Token inválido ou expirado'}
            
            # Verificar se o token está na lista de tokens ativos
            if not self.token_model.is_token_valid(payload['token_id']):
                return False, {'error': 'Token revogado'}
            
            # Verificar se o usuário ainda existe e está ativo
            user_data = self.user_model.get_user_by_id(payload['user_id'])
            if not user_data or not user_data['is_active']:
                return False, {'error': 'Usuário inativo'}
            
            # Verificar assinatura
            grace_days = current_app.config.get('SUBSCRIPTION_GRACE_DAYS', 3)
            if not self.user_model.is_subscription_valid(user_data['id'], grace_days):
                # Revogar token se assinatura expirou
                self.token_model.revoke_token(payload['token_id'])
                return False, {
                    'error': 'Assinatura expirada',
                    'code': 'SUBSCRIPTION_EXPIRED',
                    'subscription_end': user_data['subscription_end_date']
                }
            
            return True, {
                'valid': True,
                'user': {
                    'id': user_data['id'],
                    'username': user_data['username'],
                    'email': user_data['email'],
                    'subscription_end': user_data['subscription_end_date']
                },
                'token_info': {
                    'token_id': payload['token_id'],
                    'issued_at': payload['iat'],
                    'expires_at': payload['exp']
                }
            }
            
        except Exception as e:
            return False, {'error': 'Erro interno do servidor'}
    
    def logout(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Realiza logout revogando o token
        
        Args:
            token: Token JWT para revogar
            
        Returns:
            Tupla (sucesso, dados/erro)
        """
        try:
            # Obter informações do token
            payload = self.jwt_handler.get_token_info(token)
            if not payload:
                return False, {'error': 'Token inválido'}
            
            # Revogar token
            revoked = self.token_model.revoke_token(payload['token_id'])
            
            if revoked:
                return True, {'message': 'Logout realizado com sucesso'}
            else:
                return False, {'error': 'Token não encontrado'}
                
        except Exception as e:
            return False, {'error': 'Erro interno do servidor'}
    
    def extend_subscription(self, user_id: int, months: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Estende a assinatura de um usuário
        
        Args:
            user_id: ID do usuário
            months: Meses para estender
            
        Returns:
            Tupla (sucesso, dados/erro)
        """
        try:
            if months <= 0:
                return False, {'error': 'Número de meses deve ser positivo'}
            
            success = self.user_model.extend_subscription(user_id, months)
            
            if success:
                user_data = self.user_model.get_user_by_id(user_id)
                return True, {
                    'message': f'Assinatura estendida por {months} meses',
                    'new_subscription_end': user_data['subscription_end_date']
                }
            else:
                return False, {'error': 'Usuário não encontrado'}
                
        except Exception as e:
            return False, {'error': 'Erro interno do servidor'}
    
    def cleanup_expired_tokens(self) -> int:
        """
        Remove tokens expirados do banco
        
        Returns:
            Número de tokens removidos
        """
        return self.token_model.cleanup_expired_tokens()
    
    def get_user_info(self, user_id: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Obtém informações do usuário
        
        Args:
            user_id: ID do usuário
            
        Returns:
            Tupla (sucesso, dados/erro)
        """
        try:
            user_data = self.user_model.get_user_by_id(user_id)
            if not user_data:
                return False, {'error': 'Usuário não encontrado'}
            
            grace_days = current_app.config.get('SUBSCRIPTION_GRACE_DAYS', 3)
            subscription_valid = self.user_model.is_subscription_valid(user_id, grace_days)
            
            return True, {
                'user': user_data,
                'subscription_valid': subscription_valid
            }
            
        except Exception as e:
            return False, {'error': 'Erro interno do servidor'}

