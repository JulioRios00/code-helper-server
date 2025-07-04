import sqlite3
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os

class DatabaseManager:
    """Gerenciador de conexão com o banco de dados"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_database_exists()
        self._create_tables()
    
    def _ensure_database_exists(self):
        """Garante que o diretório do banco existe"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def get_connection(self):
        """Retorna uma conexão com o banco"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Para acessar colunas por nome
        return conn
    
    def _create_tables(self):
        """Cria as tabelas necessárias"""
        with self.get_connection() as conn:
            # Tabela de usuários
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    subscription_end_date TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de tokens ativos
            conn.execute('''
                CREATE TABLE IF NOT EXISTS active_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_id TEXT UNIQUE NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()

class User:
    """Modelo de usuário"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Gera hash da senha"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_user(self, username: str, email: str, password: str, 
                   subscription_months: int = 1) -> Dict[str, Any]:
        """Cria um novo usuário"""
        password_hash = self.hash_password(password)
        subscription_end = datetime.now() + timedelta(days=30 * subscription_months)
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.execute('''
                    INSERT INTO users (username, email, password_hash, subscription_end_date)
                    VALUES (?, ?, ?, ?)
                ''', (username, email, password_hash, subscription_end.isoformat()))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                return {
                    'id': user_id,
                    'username': username,
                    'email': email,
                    'subscription_end_date': subscription_end.isoformat(),
                    'is_active': True
                }
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                raise ValueError("Nome de usuário já existe")
            elif 'email' in str(e):
                raise ValueError("Email já está em uso")
            else:
                raise ValueError("Erro ao criar usuário")
    
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Autentica um usuário"""
        password_hash = self.hash_password(password)
        
        with self.db.get_connection() as conn:
            cursor = conn.execute('''
                SELECT id, username, email, subscription_end_date, is_active
                FROM users 
                WHERE username = ? AND password_hash = ? AND is_active = 1
            ''', (username, password_hash))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Busca usuário por ID"""
        with self.db.get_connection() as conn:
            cursor = conn.execute('''
                SELECT id, username, email, subscription_end_date, is_active
                FROM users 
                WHERE id = ?
            ''', (user_id,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    def is_subscription_valid(self, user_id: int, grace_days: int = 3) -> bool:
        """Verifica se a assinatura do usuário está válida"""
        user = self.get_user_by_id(user_id)
        if not user or not user['is_active']:
            return False
        
        if not user['subscription_end_date']:
            return False
        
        subscription_end = datetime.fromisoformat(user['subscription_end_date'])
        grace_period_end = subscription_end + timedelta(days=grace_days)
        
        return datetime.now() <= grace_period_end
    
    def extend_subscription(self, user_id: int, months: int) -> bool:
        """Estende a assinatura do usuário"""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        current_end = datetime.fromisoformat(user['subscription_end_date'])
        # Se a assinatura já expirou, começa da data atual
        if current_end < datetime.now():
            new_end = datetime.now() + timedelta(days=30 * months)
        else:
            new_end = current_end + timedelta(days=30 * months)
        
        with self.db.get_connection() as conn:
            conn.execute('''
                UPDATE users 
                SET subscription_end_date = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (new_end.isoformat(), user_id))
            conn.commit()
        
        return True

class Token:
    """Modelo de token"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def store_token(self, user_id: int, token_id: str, expires_at: datetime) -> bool:
        """Armazena um token ativo"""
        try:
            with self.db.get_connection() as conn:
                conn.execute('''
                    INSERT INTO active_tokens (user_id, token_id, expires_at)
                    VALUES (?, ?, ?)
                ''', (user_id, token_id, expires_at.isoformat()))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
    
    def is_token_valid(self, token_id: str) -> bool:
        """Verifica se um token está válido"""
        with self.db.get_connection() as conn:
            cursor = conn.execute('''
                SELECT expires_at FROM active_tokens 
                WHERE token_id = ?
            ''', (token_id,))
            
            row = cursor.fetchone()
            if not row:
                return False
            
            expires_at = datetime.fromisoformat(row['expires_at'])
            return datetime.now() <= expires_at
    
    def revoke_token(self, token_id: str) -> bool:
        """Revoga um token"""
        with self.db.get_connection() as conn:
            cursor = conn.execute('''
                DELETE FROM active_tokens WHERE token_id = ?
            ''', (token_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def revoke_user_tokens(self, user_id: int) -> int:
        """Revoga todos os tokens de um usuário"""
        with self.db.get_connection() as conn:
            cursor = conn.execute('''
                DELETE FROM active_tokens WHERE user_id = ?
            ''', (user_id,))
            conn.commit()
            return cursor.rowcount
    
    def cleanup_expired_tokens(self) -> int:
        """Remove tokens expirados"""
        current_time = datetime.now().isoformat()
        with self.db.get_connection() as conn:
            cursor = conn.execute('''
                DELETE FROM active_tokens WHERE expires_at < ?
            ''', (current_time,))
            conn.commit()
            return cursor.rowcount

