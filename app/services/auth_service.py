from typing import Dict, Any, Optional, Tuple
from flask import current_app
from datetime import datetime

from app.models import DatabaseManager, User, Token
from app.utils.jwt_handler import JWTHandler


class AuthService:
    """Serviço principal de autenticação usando Supabase"""

    def __init__(self):
        supabase_url = current_app.config.get('SUPABASE_URL')
        supabase_key = current_app.config.get('SUPABASE_KEY')
        supabase_signin = current_app.config.get('SUPABASE_SIGNIN')

        if not supabase_url or not supabase_key or not supabase_signin:
            raise RuntimeError("SUPABASE_URL e SUPABASE_KEY devem estar definidos nas configurações.")

        self.db_manager = DatabaseManager(supabase_url, supabase_key)
        self.user_model = User(self.db_manager, supabase_signin)
        self.token_model = Token(self.db_manager)
        self.jwt_handler = JWTHandler()

    def register_user(self, name: str, surname: str, email: str, password: str,) -> Tuple[bool, Dict[str, Any]]:
        """Registra um novo usuário"""
        try:
            if not name or len(name) < 3:
                return False, {'error': 'Nome de usuário deve ter pelo menos 3 caracteres'}
            
            if not surname or len(surname) < 3:
                return False, {'error': 'Sobrenome deve ter pelo menos 3 caracteres'}

            if not email or '@' not in email:
                return False, {'error': 'Email inválido'}

            if not password or len(password) < 6:
                return False, {'error': 'Senha deve ter pelo menos 6 caracteres'}

            user_data = self.user_model.create_user(
                name=name,
                surname=surname,
                email=email,
                password=password
            )

            return True, {
                'message': 'Usuário criado com sucesso',
                'user': user_data
            }

        except ValueError as e:
            return False, {'error': str(e)}
        except Exception as e:
            # Loga o erro para debug
            current_app.logger.error(f"Erro ao registrar usuário: {str(e)}")
            return False, {'error': 'Erro interno do servidor'}
        
    def register_user_in_supabase(self, email: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """Registra um novo usuário no supabase"""
        try:
            if not email or '@' not in email:
                return False, {'error': 'Email inválido'}

            if not password or len(password) < 6:
                return False, {'error': 'Senha deve ter pelo menos 6 caracteres'}
            
            supabase_user_data = self.user_model.create_user_in_supabase(
                email=email,
                password=password
            )

            return True, {
                'message': 'Usuário criado com sucesso no supabase',
                'user': supabase_user_data
            }

        except ValueError as e:
            return False, {'error': str(e)}
        except Exception as e:
            # Loga o erro para debug
            current_app.logger.error(f"Erro ao registrar usuário no supabase: {str(e)}")
            return False, {'error': 'Erro interno do servidor'}

    def login(self, email: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """Realiza login do usuário"""
        try:
            user_data = self.user_model.authenticate(email, password)
            if not user_data:
                return False, {'error': 'Credenciais inválidas'}

            self.token_model.store_token(
                user_id=user_data.user.id,
                token_id=user_data.user.id,
                expires_at=user_data.session.expires_at
            )

            return True, {
                'message': 'Login realizado com sucesso',
                'token': user_data.session.access_token,
                'expires_in': 86400,
                'user': {
                    'id': user_data.user.id,
                    'email': user_data.user.email,
                    'created_at': user_data.user.created_at
                }
            }
        except Exception as e:
            current_app.logger.error(f"Erro no login: {str(e)}")
            return False, {'error': 'Erro interno do servidor'}

    def validate_token(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """Valida um token JWT"""
        try:
            payload = self.jwt_handler.decode_token(token)
            if not payload:
                return False, {'error': 'Token inválido ou expirado'}

            if not self.token_model.is_token_valid(payload['token_id']):
                return False, {'error': 'Token revogado'}

            user_data = self.user_model.get_user_by_id(payload['user_id'])
            if not user_data or not user_data['is_active']:
                return False, {'error': 'Usuário inativo'}

            grace_days = current_app.config.get('SUBSCRIPTION_GRACE_DAYS', 3)
            if not self.user_model.is_subscription_valid(user_data['id'], grace_days):
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
            current_app.logger.error(f"Erro na validação do token: {str(e)}")
            return False, {'error': 'Erro interno do servidor'}

    def logout(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """Realiza logout revogando o token"""
        try:
            payload = self.jwt_handler.get_token_info(token)
            if not payload:
                return False, {'error': 'Token inválido'}

            revoked = self.token_model.revoke_token(payload['token_id'])

            if revoked:
                return True, {'message': 'Logout realizado com sucesso'}
            else:
                return False, {'error': 'Token não encontrado'}

        except Exception as e:
            current_app.logger.error(f"Erro no logout: {str(e)}")
            return False, {'error': 'Erro interno do servidor'}

    def extend_subscription(self, user_id: int, months: int) -> Tuple[bool, Dict[str, Any]]:
        """Estende a assinatura de um usuário"""
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
            current_app.logger.error(f"Erro ao estender assinatura: {str(e)}")
            return False, {'error': 'Erro interno do servidor'}

    def cleanup_expired_tokens(self) -> int:
        """Remove tokens expirados do banco"""
        try:
            return self.token_model.cleanup_expired_tokens()
        except Exception as e:
            current_app.logger.error(f"Erro ao limpar tokens expirados: {str(e)}")
            return 0

    def get_user_info(self, user_id: int) -> Tuple[bool, Dict[str, Any]]:
        """Obtém informações do usuário"""
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
            current_app.logger.error(f"Erro ao obter informações do usuário: {str(e)}")
            return False, {'error': 'Erro interno do servidor'}
