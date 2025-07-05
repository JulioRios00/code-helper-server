import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from supabase import create_client, Client


class DatabaseManager:
    """Supabase connection manager"""

    def __init__(self, url: str, key: str):
        self.supabase: Client = create_client(url, key)

    def get_connection(self) -> Client:
        return self.supabase


class User:
    def __init__(self, db: DatabaseManager, supabase_signin: str):
        self.db = db
        self.supabase_signin = supabase_signin

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def create_user(self, name: str, surname: str, email: str, password: str) -> Dict[str, Any]:
        password_hash = self.hash_password(password)
        #subscription_end = datetime.now() + timedelta(days=30 * subscription_months)

        try:
            data = {
                "name": name,
                "surname": surname,
                "email": email,
                "password_hash": password_hash,
                #"subscription_end_date": subscription_end.isoformat(),
                "is_active": True,
                "updated_at": datetime.now().isoformat(),
                "created_at": datetime.now().isoformat()
            }

            conn = self.db.get_connection()
            res = conn.table("users").insert(data).execute()
            return res.data[0] if res.data else {}

        except Exception as e:
            error_str = str(e).lower()
            if "duplicate" in error_str or "unique" in error_str:
                raise ValueError("Usuário ou email já existe")
            raise ValueError(f"Erro ao criar usuário: {str(e)}")
        
    def create_user_in_supabase(self, email: str, password: str) -> Dict[str, Any]:

        try:
            conn = self.db.get_connection()
            response = conn.auth.sign_up({
            "email": email,
            "password": password
        })

            if response.user:
                return {
                    "id": response.user.id,
                    "email": response.user.email,
                    "created_at": response.user.created_at
                }
            else:
                raise ValueError("Erro ao criar usuário: resposta inesperada")

        except Exception as e:
            error_str = str(e).lower()
            if "user already registered" in error_str or "duplicate" in error_str:
                raise ValueError("Usuário ou email já existe")
            raise ValueError(f"Erro ao criar usuário: {str(e)}")

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        password_hash = self.hash_password(password)
        conn = self.db.get_connection()
        res = conn.table("users").select("*").eq("username", username).eq("password_hash", password_hash).eq("is_active", True).execute()
        return res.data[0] if res.data else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        conn = self.db.get_connection()
        res = conn.table("users").select("*").eq("id", user_id).execute()
        return res.data[0] if res.data else None

    def is_subscription_valid(self, user_id: int, grace_days: int = 3) -> bool:
        user = self.get_user_by_id(user_id)
        if not user or not user.get('is_active'):
            return False
        end_date = user.get('subscription_end_date')
        if not end_date:
            return False
        end = datetime.fromisoformat(end_date)
        return datetime.now() <= end + timedelta(days=grace_days)

    def extend_subscription(self, user_id: int, months: int) -> bool:
        user = self.get_user_by_id(user_id)
        if not user:
            return False

        current_end = datetime.fromisoformat(user['subscription_end_date'])
        new_end = max(current_end, datetime.now()) + timedelta(days=30 * months)

        conn = self.db.get_connection()
        conn.table("users").update({"subscription_end_date": new_end.isoformat()}).eq("id", user_id).execute()
        return True


class Token:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def store_token(self, user_id: int, token_id: str, expires_at: datetime) -> bool:
        try:
            conn = self.db.get_connection()
            conn.table("active_tokens").insert({
                "user_id": user_id,
                "token_id": token_id,
                "expires_at": expires_at.isoformat(),
                "created_at": datetime.now().isoformat()
            }).execute()
            return True
        except Exception:
            return False

    def is_token_valid(self, token_id: str) -> bool:
        conn = self.db.get_connection()
        res = conn.table("active_tokens").select("expires_at").eq("token_id", token_id).execute()
        if not res.data:
            return False
        expires_at = datetime.fromisoformat(res.data[0]['expires_at'])
        return datetime.now() <= expires_at

    def revoke_token(self, token_id: str) -> bool:
        conn = self.db.get_connection()
        res = conn.table("active_tokens").delete().eq("token_id", token_id).execute()
        return res.count > 0

    def revoke_user_tokens(self, user_id: int) -> int:
        conn = self.db.get_connection()
        res = conn.table("active_tokens").delete().eq("user_id", user_id).execute()
        return res.count or 0

    def cleanup_expired_tokens(self) -> int:
        now = datetime.now().isoformat()
        conn = self.db.get_connection()
        res = conn.table("active_tokens").delete().lt("expires_at", now).execute()
        return res.count or 0
