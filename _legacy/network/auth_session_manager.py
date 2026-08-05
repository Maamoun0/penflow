import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

@dataclass
class AuthProfile:
    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    user_id: Optional[str] = None

class AuthSessionManager:
    """Manages multi-account authentication profiles (User A, User B, Unauthenticated)."""
    
    def __init__(self):
        self.profiles: Dict[str, AuthProfile] = {}
        
    def set_profile(self, name: str, headers: Dict[str, str] = None, cookies: Dict[str, str] = None, user_id: str = None) -> AuthProfile:
        headers = headers or {}
        cookies = cookies or {}
        
        profile = AuthProfile(
            name=name,
            headers=headers,
            cookies=cookies,
            user_id=user_id
        )
        self.profiles[name] = profile
        return profile
        
    def get_profile(self, name: str) -> Optional[AuthProfile]:
        return self.profiles.get(name)
        
    def get_headers_for(self, name: str) -> Dict[str, str]:
        profile = self.get_profile(name)
        if not profile:
            return {}
            
        headers = profile.headers.copy()
        if profile.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in profile.cookies.items()])
            headers["Cookie"] = cookie_str
            
        return headers

    def to_dict(self) -> Dict[str, Any]:
        return {
            name: {
                "headers": p.headers,
                "cookies": p.cookies,
                "user_id": p.user_id
            } for name, p in self.profiles.items()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthSessionManager":
        manager = cls()
        for name, p_data in data.items():
            manager.set_profile(
                name=name,
                headers=p_data.get("headers", {}),
                cookies=p_data.get("cookies", {}),
                user_id=p_data.get("user_id")
            )
        return manager
