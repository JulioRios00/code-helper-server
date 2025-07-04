import os
from datetime import timedelta

class Config:
    """Configurações base da aplicação"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sua-chave-secreta-super-segura-aqui'
    
    # Configurações do JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-chave-secreta-super-segura'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Token expira em 24 horas
    
    # Configurações do banco de dados
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'users.db')
    
    # Configurações de CORS
    CORS_ORIGINS = "*"  # Permite todas as origens em desenvolvimento
    
    # Configurações de assinatura
    SUBSCRIPTION_GRACE_DAYS = 3  # Dias de tolerância após vencimento

class DevelopmentConfig(Config):
    """Configurações para desenvolvimento"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Configurações para produção"""
    DEBUG = False
    TESTING = False
    # Em produção, use variáveis de ambiente para chaves secretas
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

class TestingConfig(Config):
    """Configurações para testes"""
    DEBUG = True
    TESTING = True
    DATABASE_PATH = ':memory:'  # Banco em memória para testes

# Configuração padrão
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

