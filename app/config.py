import os
from datetime import timedelta

class Config:
    """Configurações base da aplicação"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sua-chave-secreta-super-segura-aqui'
    
    # Configurações do JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-chave-secreta-super-segura'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Token expira em 24 horas
    
    SUPABASE_URL = os.environ.get('SUPABASE_URL') or 'https://ozbafgaynzaaphyofswv.supabase.co'
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY') or 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im96YmFmZ2F5bnphYXBoeW9mc3d2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE2NTY0NTIsImV4cCI6MjA2NzIzMjQ1Mn0.4nrCF5VgAL9auS-SVYzvxJRiIPqRUI8El6D-56gbbOQ'
    
    # Configurações de CORS
    CORS_ORIGINS = "*"  # Permite todas as origens em desenvolvimento
    
    # Configurações de assinatura
    SUBSCRIPTION_GRACE_DAYS = 3  # Dias de tolerância após vencimento

class DevelopmentConfig(Config):
    """Configurações para desenvolvimento"""
    DEBUG = True
    TESTING = False
    SUPABASE_URL = os.environ.get('SUPABASE_URL') or 'https://ozbafgaynzaaphyofswv.supabase.co'
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY') or 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im96YmFmZ2F5bnphYXBoeW9mc3d2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE2NTY0NTIsImV4cCI6MjA2NzIzMjQ1Mn0.4nrCF5VgAL9auS-SVYzvxJRiIPqRUI8El6D-56gbbOQ'
    

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
    
    SUPABASE_URL = os.environ.get('SUPABASE_URL') or 'https://<seu-projeto>.supabase.co'
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY') or '<sua-service-role-key>'

# Configuração padrão
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

