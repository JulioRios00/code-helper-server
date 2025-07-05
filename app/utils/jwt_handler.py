import jwt
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from flask import current_app

class JWTHandler:
    """Manipulador de tokens JWT"""
    
    @staticmethod
    def generate_token(user_data: Dict[str, Any], expires_in_hours: int = 24) -> Dict[str, Any]:
        """
        Gera um token JWT para o usuário
        
        Args:
            user_data: Dados do usuário (id, username, email)
            expires_in_hours: Tempo de expiração em horas
            
        Returns:
            Dict contendo o token e informações de expiração
        """
        # ID único para o token
        token_id = str(uuid.uuid4())
        
        # Tempo de expiração
        expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
        
        # Payload do token
        payload = {
            'user_id': user_data['id'],
            'name': user_data['name'],
            'surname': user_data['surname'],
            'email': user_data['email'],
            'token_id': token_id,
            'iat': datetime.utcnow(),  # Issued at
            'exp': expires_at,        # Expiration time
            'iss': 'auth-server',     # Issuer
        }
        
        # Gerar o token
        token = jwt.encode(
            payload, 
            current_app.config['JWT_SECRET_KEY'], 
            algorithm='HS256'
        )
        
        return {
            'token': token,
            'token_id': token_id,
            'expires_at': expires_at,
            'expires_in': expires_in_hours * 3600  # Em segundos
        }
    
    @staticmethod
    def decode_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Decodifica e valida um token JWT
        
        Args:
            token: Token JWT para decodificar
            
        Returns:
            Payload do token se válido, None caso contrário
        """
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256'],
                options={'verify_exp': True}
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    @staticmethod
    def extract_token_from_header(auth_header: str) -> Optional[str]:
        """
        Extrai o token do cabeçalho Authorization
        
        Args:
            auth_header: Cabeçalho Authorization (formato: "Bearer <token>")
            
        Returns:
            Token extraído ou None se inválido
        """
        if not auth_header:
            return None
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return None
        
        return parts[1]
    
    @staticmethod
    def get_token_info(token: str) -> Optional[Dict[str, Any]]:
        """
        Obtém informações do token sem validar expiração
        
        Args:
            token: Token JWT
            
        Returns:
            Informações do token ou None se inválido
        """
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256'],
                options={'verify_exp': False}  # Não verifica expiração
            )
            return payload
        except jwt.InvalidTokenError:
            return None

