#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Business Gemini OpenAPI 兼容服务
整合JWT获取和聊天功能，提供OpenAPI接口
支持多账号轮询、自动冷却、故障转移和自动刷新
"""

import os
import re
import json
import time
import hmac
import uuid
import base64
import logging
import hashlib
import threading
import queue
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from functools import wraps

import requests
import urllib3
from flask import Flask, request, Response, jsonify
from flask_cors import CORS

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== 全局配置 ====================
CONFIG = {
    # 管理员密钥（优先从环境变量读取）
    "admin_key": os.getenv("ADMIN_KEY", "admin123"),
    
    # 注册服务URL前缀（从环境变量读取）
    "register_service_url": os.getenv("REGISTER_SERVICE_URL", "http://localhost:5000"),

    #注册服务管理员密钥（从环境变量读取）
    "register_admin_key": os.getenv("REGISTER_ADMIN_KEY", "sk-admin-token"),
    # 账号生命周期（秒）- 默认12小时
    "account_lifetime": int(os.getenv("ACCOUNT_LIFETIME", 43200)),
    
    # 提前刷新时间（秒）- 默认1小时
    "refresh_before_expiry": int(os.getenv("REFRESH_BEFORE_EXPIRY", 3600)),
    
    # 刷新队列批量大小
    "refresh_batch_size": int(os.getenv("REFRESH_BATCH_SIZE", 1)),
    
    # 最大重试次数
    "max_retries": int(os.getenv("MAX_RETRIES", 10)),
    
    # 模型映射配置
    "models": {
        "gemini-2.5-flash": {"base": "gemini-2.5-flash", "tools": {}},
        "gemini-2.5-flash-search": {"base": "gemini-2.5-flash", "tools": {"webGroundingSpec": {}}},
        "gemini-2.5-pro": {"base": "gemini-2.5-pro", "tools": {}},
        "gemini-2.5-pro-search": {"base": "gemini-2.5-pro", "tools": {"webGroundingSpec": {}}},
        "gemini-3-pro-preview": {"base": "gemini-3-pro-preview", "tools": {}},
        "gemini-3-pro-preview-search": {"base": "gemini-3-pro-preview", "tools": {"webGroundingSpec": {}}},
        "banana-pro": {"base": "gemini-3-pro-preview", "tools": {"imageGenerationSpec": {}}},
    },
    
    # 账号冷却时间配置（秒）
    "cooldown": {
        "auth_error": 900,
        "rate_limit": 300,
        "generic_error": 120,
    },
    
    # JWT有效期（秒）
    "jwt_lifetime": 240,
    
    # 日志级别
    "log_level": os.getenv("LOG_LEVEL", "INFO"),
}

# API端点
API_ENDPOINTS = {
    "base": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global",
    "create_session": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetCreateSession",
    "stream_assist": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetStreamAssist",
    "add_context_file": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetAddContextFile",
    "list_file_metadata": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetListSessionFileMetadata",
    "get_oxsrf": "https://business.gemini.google/auth/getoxsrf",
}

# ==================== 日志配置 ====================
def setup_logger():
    """配置日志系统"""
    logger = logging.getLogger("BusinessGemini")
    logger.setLevel(getattr(logging, CONFIG["log_level"].upper(), logging.INFO))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    return logger

logger = setup_logger()

# ==================== 异常定义 ====================
class AccountError(Exception):
    """账号相关基础异常"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AccountAuthError(AccountError):
    """凭证/权限异常 - 需要刷新账号"""
    pass


class AccountRateLimitError(AccountError):
    """配额/限流异常"""
    pass


class AccountRequestError(AccountError):
    """请求异常"""
    pass


class NoAvailableAccountError(AccountError):
    """无可用账号异常"""
    pass

# ==================== 工具函数 ====================
def url_safe_b64encode(data: bytes) -> str:
    """URL安全的Base64编码"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def kq_encode(s: str) -> str:
    """模拟JS的kQ函数编码"""
    byte_arr = bytearray()
    for char in s:
        val = ord(char)
        if val > 255:
            byte_arr.append(val & 255)
            byte_arr.append(val >> 8)
        else:
            byte_arr.append(val)
    return url_safe_b64encode(bytes(byte_arr))


def decode_xsrf_token(xsrf_token: str) -> bytes:
    """解码xsrfToken为字节数组"""
    padding = 4 - len(xsrf_token) % 4
    if padding != 4:
        xsrf_token += '=' * padding
    return base64.urlsafe_b64decode(xsrf_token)


def parse_base64_data_url(data_url: str) -> Optional[Dict]:
    """解析base64数据URL"""
    if not data_url or not data_url.startswith("data:"):
        return None
    match = re.match(r"data:([^;]+);base64,(.+)", data_url)
    if match:
        return {"mime_type": match.group(1), "data": match.group(2)}
    return None


def parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    """解析ISO格式时间字符串"""
    if not dt_str:
        return None
    try:
        # 尝试多种格式
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                return datetime.strptime(dt_str.replace('Z', '').split('+')[0], fmt)
            except ValueError:
                continue
        return None
    except:
        return None


def seconds_until_pt_midnight() -> int:
    """计算距离下一个太平洋时间午夜的秒数"""
    try:
        from zoneinfo import ZoneInfo
        pt_tz = ZoneInfo("America/Los_Angeles")
        now_pt = datetime.now(pt_tz)
    except ImportError:
        now_utc = datetime.now(timezone.utc)
        now_pt = now_utc - timedelta(hours=8)
    
    tomorrow = (now_pt + timedelta(days=1)).date()
    midnight_pt = datetime.combine(tomorrow, datetime.min.time())
    if hasattr(now_pt, 'tzinfo') and now_pt.tzinfo:
        midnight_pt = midnight_pt.replace(tzinfo=now_pt.tzinfo)
    delta = (midnight_pt - now_pt).total_seconds()
    return max(0, int(delta))


def get_headers(jwt: str) -> Dict:
    """获取请求头"""
    return {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json",
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "x-server-timeout": "1800",
    }

# ==================== JWT管理模块 ====================
class JWTManager:
    """JWT令牌管理器"""
    
    @staticmethod
    def create_jwt(key_bytes: bytes, key_id: str, csesidx: str) -> str:
        """创建JWT令牌"""
        now = int(time.time())
        
        header = {"alg": "HS256", "typ": "JWT", "kid": key_id}
        payload = {
            "iss": "https://business.gemini.google",
            "aud": "https://biz-discoveryengine.googleapis.com",
            "sub": f"csesidx/{csesidx}",
            "iat": now,
            "exp": now + 300,
            "nbf": now
        }
        
        header_b64 = kq_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = kq_encode(json.dumps(payload, separators=(',', ':')))
        message = f"{header_b64}.{payload_b64}"
        
        signature = hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).digest()
        signature_b64 = url_safe_b64encode(signature)
        
        return f"{message}.{signature_b64}"
    
    @staticmethod
    def fetch_jwt(account: Dict) -> str:
        """获取账号的JWT令牌"""
        secure_c_ses = account.get("secure_c_ses")
        host_c_oses = account.get("host_c_oses")
        csesidx = account.get("csesidx")
        
        if not secure_c_ses or not csesidx:
            raise AccountAuthError("账号缺少secure_c_ses或csesidx")
        
        url = f"{API_ENDPOINTS['get_oxsrf']}?csesidx={csesidx}"
        headers = {
            "accept": "*/*",
            "user-agent": account.get('user_agent', 'Mozilla/5.0'),
            "cookie": f'__Secure-C_SES={secure_c_ses}; __Host-C_OSES={host_c_oses}',
        }
        
        try:
            resp = requests.get(url, headers=headers, timeout=30, verify=False)
        except requests.RequestException as e:
            raise AccountRequestError(f"获取JWT请求失败: {e}")
        
        if resp.status_code == 401:
            raise AccountAuthError("JWT获取失败: 401 未授权", 401)
        
        if resp.status_code != 200:
            JWTManager._handle_error_response(resp, "获取JWT")
        
        text = resp.text
        if text.startswith(")]}'\n") or text.startswith(")]}'"):
            text = text[4:].strip()
        
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise AccountAuthError(f"解析JWT响应失败: {e}")
        
        key_id = data.get("keyId")
        xsrf_token = data.get("xsrfToken")
        
        if not key_id or not xsrf_token:
            raise AccountAuthError(f"JWT响应缺少keyId或xsrfToken")
        
        logger.info(f"账号 {csesidx} JWT获取成功")
        key_bytes = decode_xsrf_token(xsrf_token)
        return JWTManager.create_jwt(key_bytes, key_id, csesidx)
    
    @staticmethod
    def _handle_error_response(resp: requests.Response, action: str):
        """处理错误响应"""
        status = resp.status_code
        body = resp.text[:500] if resp.text else ""
        lower_body = body.lower()
        
        if status in (401, 403):
            raise AccountAuthError(f"{action}认证失败: {status}", status)
        if status == 429 or any(kw in lower_body for kw in ["quota", "exceed", "limit"]):
            raise AccountRateLimitError(f"{action}触发限流: {status}", status)
        raise AccountRequestError(f"{action}请求失败: {status}", status)

# ==================== 文件上传与下载模块 ====================
class FileManager:
    """文件管理器，处理上传和下载"""
    
    @staticmethod
    def upload_image(jwt: str, session_name: str, team_id: str, image_data: Dict) -> Optional[str]:
        """上传图片到Gemini，返回fileId"""
        try:
            mime_type = image_data.get("mime_type", "image/png")
            b64_data = image_data.get("data", "")
            
            ext_map = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp"}
            ext = ext_map.get(mime_type, ".png")
            filename = f"upload_{uuid.uuid4().hex[:8]}{ext}"
            
            body = {
                "addContextFileRequest": {
                    "fileContents": b64_data,
                    "fileName": filename,
                    "mimeType": mime_type,
                    "name": session_name
                },
                "additionalParams": {"token": "-"},
                "configId": team_id
            }
            
            resp = requests.post(
                API_ENDPOINTS["add_context_file"],
                headers=get_headers(jwt),
                json=body,
                timeout=60,
                verify=False
            )
            
            if resp.status_code != 200:
                logger.warning(f"图片上传失败: {resp.status_code}")
                return None
            
            data = resp.json()
            file_id = data.get("addContextFileResponse", {}).get("fileId")
            if file_id:
                logger.info(f"图片上传成功: {file_id}")
            return file_id
            
        except Exception as e:
            logger.error(f"图片上传异常: {e}")
            return None
    
    @staticmethod
    def get_session_file_metadata(jwt: str, session_name: str, team_id: str) -> Dict:
        """获取会话中的文件元数据"""
        body = {
            "configId": team_id,
            "additionalParams": {"token": "-"},
            "listSessionFileMetadataRequest": {
                "name": session_name,
                "filter": "file_origin_type = AI_GENERATED"
            }
        }
        
        try:
            resp = requests.post(
                API_ENDPOINTS["list_file_metadata"],
                headers=get_headers(jwt),
                json=body,
                verify=False,
                timeout=30
            )
            
            if resp.status_code != 200:
                return {}
            
            data = resp.json()
            result = {}
            file_metadata_list = data.get("listSessionFileMetadataResponse", {}).get("fileMetadata", [])
            for meta in file_metadata_list:
                file_id = meta.get("fileId")
                if file_id:
                    result[file_id] = meta
            return result
            
        except Exception as e:
            logger.error(f"获取文件元数据异常: {e}")
            return {}
    
    @staticmethod
    def build_download_url(session_name: str, file_id: str) -> str:
        """构造下载URL"""
        return f"https://biz-discoveryengine.googleapis.com/v1alpha/{session_name}:downloadFile?fileId={file_id}&alt=media"
    
    @staticmethod
    def download_file(jwt: str, session_name: str, file_id: str) -> Optional[bytes]:
        """下载文件"""
        url = FileManager.build_download_url(session_name, file_id)
        
        try:
            resp = requests.get(
                url,
                headers=get_headers(jwt),
                verify=False,
                timeout=120,
                allow_redirects=True
            )
            resp.raise_for_status()
            return resp.content
            
        except Exception as e:
            logger.error(f"文件下载失败 (fileId={file_id}): {e}")
            return None

# ==================== 账号刷新服务 ====================
class AccountRefreshService:
    """账号刷新服务 - 调用注册服务API刷新账号"""
    
    def __init__(self, base_url: str, register_admin_key: str):
        self.base_url = base_url.rstrip('/')
        self.register_admin_key = register_admin_key
    
    def _get_auth_headers(self) -> Dict:
        """获取认证头"""
        credentials = self.register_admin_key
        return {
            "Authorization": f"Bearer {credentials}",
            "Content-Type": "application/json"
        }
    
    def refresh_account(self, email: str, max_wait: int = 300) -> Optional[Dict]:
        """
        请求刷新账号
        - 注册服务会自动处理：
          - 如果账号存在，直接刷新
          - 如果账号不存在但域名匹配，自动创建并刷新
        返回刷新后的账号信息，失败返回None
        """
        try:
            # 调用刷新接口
            url = f"{self.base_url}/api/accounts/{email}/refresh"
            resp = requests.post(url, headers=self._get_auth_headers(), timeout=30)
            
            if resp.status_code == 429:
                logger.warning(f"刷新账号请求被限流: {email}")
                return None
            
            if resp.status_code == 404:
                logger.warning(f"邮箱域名未配置，无法刷新: {email}")
                return None
            
            if resp.status_code != 200:
                logger.warning(f"刷新账号请求失败: {resp.status_code} - {resp.text}")
                return None
            
            data = resp.json()
            if not data.get("success"):
                logger.warning(f"刷新账号失败: {data.get('error')}")
                return None
            
            logger.info(f"账号 {email} 刷新请求已发送")
            
            # 轮询等待刷新完成
            return self._wait_for_refresh(email, max_wait)
            
        except Exception as e:
            logger.error(f"刷新账号异常: {e}")
            return None
    
    def _wait_for_refresh(self, email: str, max_wait: int = 300, interval: int = 5) -> Optional[Dict]:
        """等待刷新完成"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                url = f"{self.base_url}/api/accounts?email={email}"
                resp = requests.get(url, headers=self._get_auth_headers(), timeout=30)
                
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success") and data.get("account"):
                        account = data["account"]
                        status = account.get("status")
                        
                        if status == "success" and account.get("is_complete"):
                            logger.info(f"账号 {email} 刷新成功")
                            return {
                                "email": email,
                                "secure_c_ses": account.get("c_ses"),
                                "host_c_oses": account.get("c_oses"),
                                "csesidx": account.get("csesidx"),
                                "team_id": account.get("config_id"),
                                "updated_at": account.get("updated_at") or datetime.now().isoformat()
                            }
                        elif status == "failed":
                            logger.warning(f"账号 {email} 刷新失败: {account.get('error_message')}")
                            return None
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"等待刷新异常: {e}")
                time.sleep(interval)
        
        logger.warning(f"账号 {email} 刷新超时")
        return None
    
    def batch_refresh(self, emails: List[str]) -> Dict[str, Optional[Dict]]:
        """批量刷新账号"""
        results = {}
        for email in emails:
            results[email] = self.refresh_account(email)
        return results


# ==================== 账号管理模块 ====================
@dataclass
class AccountState:
    """账号状态"""
    jwt: Optional[str] = None
    jwt_time: float = 0
    session: Optional[str] = None
    available: bool = True
    cooldown_until: Optional[float] = None
    cooldown_reason: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    needs_refresh: bool = False
    refresh_in_progress: bool = False


class AccountManager:
    """账号池管理器 - 支持生命周期管理"""
    
    def __init__(self, refresh_service: AccountRefreshService):
        self.accounts: List[Dict] = []
        self.states: Dict[int, AccountState] = {}
        self.current_index: int = 0
        self.lock = threading.Lock()
        self.refresh_service = refresh_service
        self.refresh_queue = queue.Queue()
        self.refresh_thread: Optional[threading.Thread] = None
        self.running = True
    
    def start_refresh_worker(self):
        """启动刷新工作线程"""
        self.refresh_thread = threading.Thread(target=self._refresh_worker, daemon=True)
        self.refresh_thread.start()
        
        # 启动生命周期检查线程
        check_thread = threading.Thread(target=self._lifecycle_checker, daemon=True)
        check_thread.start()
        
        logger.info("账号刷新工作线程已启动")
    
    def _refresh_worker(self):
        """刷新工作线程"""
        while self.running:
            try:
                # 获取批量任务
                batch = []
                batch_size = CONFIG["refresh_batch_size"]
                
                try:
                    item = self.refresh_queue.get(timeout=5)
                    batch.append(item)
                    
                    # 尝试获取更多任务
                    while len(batch) < batch_size:
                        try:
                            item = self.refresh_queue.get_nowait()
                            batch.append(item)
                        except queue.Empty:
                            break
                            
                except queue.Empty:
                    continue
                
                # 处理批量刷新
                for account_idx in batch:
                    self._do_refresh(account_idx)
                    
            except Exception as e:
                logger.error(f"刷新工作线程异常: {e}")
    
    def _do_refresh(self, account_idx: int):
        """执行账号刷新"""
        with self.lock:
            if account_idx >= len(self.accounts):
                return
            account = self.accounts[account_idx]
            state = self.states.get(account_idx)
            if not state:
                return
            state.refresh_in_progress = True
        
        try:
            # 使用邮箱作为刷新标识
            email = account.get("email")
            if not email:
                # 如果没有邮箱，无法刷新
                logger.warning(f"账号 {account_idx} 没有邮箱，无法刷新")
                return
            
            logger.info(f"开始刷新账号 {account_idx}: {email}")
            
            # 调用刷新服务 - 注册服务会自动处理账号不存在的情况
            result = self.refresh_service.refresh_account(email)
            
            if result:
                # 更新账号信息
                with self.lock:
                    if account_idx < len(self.accounts):
                        self.accounts[account_idx].update({
                            "email": result.get("email", email),
                            "secure_c_ses": result.get("secure_c_ses"),
                            "host_c_oses": result.get("host_c_oses"),
                            "csesidx": result.get("csesidx"),
                            "team_id": result.get("team_id"),
                            "updated_at": result.get("updated_at"),
                        })
                        
                        state = self.states.get(account_idx)
                        if state:
                            state.jwt = None
                            state.jwt_time = 0
                            state.session = None
                            state.updated_at = datetime.now()
                            state.needs_refresh = False
                            state.cooldown_until = None
                            state.cooldown_reason = ""
                            state.available = True
                        
                        logger.info(f"账号 {account_idx} ({email}) 刷新成功")
            else:
                logger.warning(f"账号 {account_idx} ({email}) 刷新失败")
                
        except Exception as e:
            logger.error(f"账号 {account_idx} 刷新异常: {e}")
        finally:
            with self.lock:
                state = self.states.get(account_idx)
                if state:
                    state.refresh_in_progress = False

    
    def _lifecycle_checker(self):
        """生命周期检查线程"""
        while self.running:
            try:
                self._check_account_lifetimes()
                time.sleep(60)  # 每分钟检查一次
            except Exception as e:
                logger.error(f"生命周期检查异常: {e}")
    
    def _check_account_lifetimes(self):
        """检查账号生命周期"""
        now = datetime.now()
        lifetime = CONFIG["account_lifetime"]
        refresh_before = CONFIG["refresh_before_expiry"]
        
        with self.lock:
            for i, account in enumerate(self.accounts):
                state = self.states.get(i)
                if not state or not state.available:
                    continue
                
                if state.refresh_in_progress or state.needs_refresh:
                    continue
                
                # 获取最后更新时间
                last_update = state.updated_at or state.created_at
                if not last_update:
                    # 从账号数据获取
                    updated_at_str = account.get("updated_at") or account.get("created_at")
                    last_update = parse_iso_datetime(updated_at_str)
                    if last_update:
                        state.updated_at = last_update
                
                if not last_update:
                    continue
                
                # 计算剩余时间
                age = (now - last_update).total_seconds()
                remaining = lifetime - age
                
                # 如果剩余时间小于提前刷新时间，加入刷新队列
                if remaining <= refresh_before and remaining > 0:
                    state.needs_refresh = True
                    self.refresh_queue.put(i)
                    logger.info(f"账号 {i} 即将过期（剩余 {int(remaining)} 秒），已加入刷新队列")
    
    def load_accounts(self, accounts: List[Dict]):
        """加载账号列表"""
        with self.lock:
            self.accounts = accounts
            self.states = {}
            
            for i, acc in enumerate(accounts):
                # 解析时间
                created_at = parse_iso_datetime(acc.get("created_at"))
                updated_at = parse_iso_datetime(acc.get("updated_at"))
                
                self.states[i] = AccountState(
                    available=acc.get("available", True),
                    cooldown_until=acc.get("cooldown_until"),
                    cooldown_reason=acc.get("cooldown_reason", ""),
                    created_at=created_at,
                    updated_at=updated_at or created_at,
                )
            
            logger.info(f"已加载 {len(accounts)} 个账号")
    
    def get_accounts_json(self) -> List[Dict]:
        """获取账号列表JSON"""
        with self.lock:
            result = []
            now = time.time()
            now_dt = datetime.now()
            lifetime = CONFIG["account_lifetime"]
            
            for i, acc in enumerate(self.accounts):
                state = self.states.get(i, AccountState())
                cooldown_remaining = 0
                if state.cooldown_until and state.cooldown_until > now:
                    cooldown_remaining = int(state.cooldown_until - now)
                
                # 计算生命周期剩余时间
                lifetime_remaining = 0
                last_update = state.updated_at or state.created_at
                if last_update:
                    age = (now_dt - last_update).total_seconds()
                    lifetime_remaining = max(0, int(lifetime - age))
                
                result.append({
                    "id": i,
                    "team_id": acc.get("team_id", ""),
                    "csesidx": acc.get("csesidx", ""),
                    "email": acc.get("email", ""),
                    "user_agent": acc.get("user_agent", "")[:50] + "..." if len(acc.get("user_agent", "")) > 50 else acc.get("user_agent", ""),
                    "available": self._is_available(i),
                    "cooldown_remaining": cooldown_remaining,
                    "cooldown_reason": state.cooldown_reason if cooldown_remaining > 0 else "",
                    "lifetime_remaining": lifetime_remaining,
                    "needs_refresh": state.needs_refresh,
                    "refresh_in_progress": state.refresh_in_progress,
                    "has_jwt": state.jwt is not None,
                    "created_at": state.created_at.isoformat() if state.created_at else "",
                    "updated_at": state.updated_at.isoformat() if state.updated_at else "",
                })
            return result
    
    def _is_available(self, index: int) -> bool:
        """检查账号是否可用"""
        state = self.states.get(index)
        if not state or not state.available:
            return False
        if state.cooldown_until and state.cooldown_until > time.time():
            return False
        if state.refresh_in_progress:
            return False
        return True
    
    def get_available_count(self) -> Tuple[int, int]:
        """获取账号统计"""
        total = len(self.accounts)
        available = sum(1 for i in range(total) if self._is_available(i))
        return total, available
    
    def get_next_account(self) -> Tuple[int, Dict]:
        """轮询获取下一个可用账号"""
        with self.lock:
            available_accounts = [
                (i, acc) for i, acc in enumerate(self.accounts)
                if self._is_available(i)
            ]
            
            if not available_accounts:
                next_cooldown = self._get_next_cooldown()
                if next_cooldown:
                    remaining = int(max(0, next_cooldown - time.time()))
                    raise NoAvailableAccountError(f"无可用账号，最近冷却结束约 {remaining} 秒后")
                raise NoAvailableAccountError("无可用账号")
            
            self.current_index = self.current_index % len(available_accounts)
            idx, account = available_accounts[self.current_index]
            self.current_index = (self.current_index + 1) % len(available_accounts)
            return idx, account
    
    def _get_next_cooldown(self) -> Optional[float]:
        """获取最近的冷却结束时间"""
        now = time.time()
        cooldowns = [
            s.cooldown_until for s in self.states.values()
            if s.cooldown_until and s.cooldown_until > now
        ]
        return min(cooldowns) if cooldowns else None
    
    def set_cooldown(self, index: int, reason: str, seconds: int):
        """设置账号冷却"""
        with self.lock:
            if index not in self.states:
                return
            state = self.states[index]
            state.cooldown_until = time.time() + seconds
            state.cooldown_reason = reason
            state.jwt = None
            state.jwt_time = 0
            state.session = None
            logger.warning(f"账号 {index} 进入冷却 {seconds} 秒: {reason}")
    
    def trigger_refresh(self, index: int):
        """触发账号刷新（用于401错误）"""
        with self.lock:
            if index not in self.states:
                return
            state = self.states[index]
            if not state.refresh_in_progress and not state.needs_refresh:
                state.needs_refresh = True
                state.available = False  # 暂时禁用
                self.refresh_queue.put(index)
                logger.info(f"账号 {index} 触发刷新（401错误）")
    
    def toggle_account(self, index: int) -> bool:
        """切换账号启用状态"""
        with self.lock:
            if index not in self.states:
                return False
            state = self.states[index]
            state.available = not state.available
            if state.available:
                state.cooldown_until = None
                state.cooldown_reason = ""
            logger.info(f"账号 {index} 状态切换为: {'启用' if state.available else '禁用'}")
            return state.available
    
    def update_account(self, index: int, data: Dict) -> bool:
        """更新账号信息"""
        with self.lock:
            if index < 0 or index >= len(self.accounts):
                return False
            for key in ["team_id", "secure_c_ses", "host_c_oses", "csesidx", "user_agent", "email"]:
                if key in data:
                    self.accounts[index][key] = data[key]
            if index in self.states:
                self.states[index].jwt = None
                self.states[index].jwt_time = 0
                self.states[index].session = None
                self.states[index].updated_at = datetime.now()
            logger.info(f"账号 {index} 信息已更新")
            return True
    
    def delete_account(self, index: int) -> bool:
        """删除账号"""
        with self.lock:
            if index < 0 or index >= len(self.accounts):
                return False
            self.accounts.pop(index)
            new_states = {}
            for i in range(len(self.accounts)):
                if i < index:
                    new_states[i] = self.states.get(i, AccountState())
                else:
                    new_states[i] = self.states.get(i + 1, AccountState())
            self.states = new_states
            logger.info(f"账号 {index} 已删除")
            return True
    
    def add_account(self, account: Dict) -> int:
        """添加账号"""
        with self.lock:
            self.accounts.append(account)
            idx = len(self.accounts) - 1
            
            created_at = parse_iso_datetime(account.get("created_at"))
            updated_at = parse_iso_datetime(account.get("updated_at"))
            
            self.states[idx] = AccountState(
                created_at=created_at or datetime.now(),
                updated_at=updated_at or created_at or datetime.now(),
            )
            logger.info(f"新账号已添加，索引: {idx}")
            return idx
    
    def ensure_jwt(self, index: int, account: Dict) -> str:
        """确保账号JWT有效"""
        with self.lock:
            state = self.states.get(index)
            if not state:
                state = AccountState()
                self.states[index] = state
            
            jwt_age = time.time() - state.jwt_time if state.jwt else float('inf')
            
            if state.jwt and jwt_age <= CONFIG["jwt_lifetime"]:
                return state.jwt
        
        jwt = JWTManager.fetch_jwt(account)
        
        with self.lock:
            state = self.states.get(index, AccountState())
            state.jwt = jwt
            state.jwt_time = time.time()
            self.states[index] = state
        
        return jwt
    
    def ensure_session(self, index: int, account: Dict) -> Tuple[str, str, str]:
        """确保会话有效"""
        jwt = self.ensure_jwt(index, account)
        
        with self.lock:
            state = self.states.get(index)
            if state and state.session:
                return state.session, jwt, account.get("team_id", "")
        
        session = SessionManager.create_session(jwt, account.get("team_id", ""))
        
        with self.lock:
            if index in self.states:
                self.states[index].session = session
        
        return session, jwt, account.get("team_id", "")
    
    def force_refresh_all(self):
        """强制刷新所有账号"""
        with self.lock:
            for i in range(len(self.accounts)):
                state = self.states.get(i)
                if state and state.available and not state.refresh_in_progress:
                    state.needs_refresh = True
                    self.refresh_queue.put(i)
        logger.info("已将所有账号加入刷新队列")


# ==================== 会话管理模块 ====================
class SessionManager:
    """会话管理器"""
    
    @staticmethod
    def create_session(jwt: str, team_id: str) -> str:
        """创建聊天会话"""
        session_id = uuid.uuid4().hex[:12]
        body = {
            "configId": team_id,
            "additionalParams": {"token": "-"},
            "createSessionRequest": {
                "session": {"name": session_id, "displayName": session_id}
            }
        }
        
        try:
            resp = requests.post(
                API_ENDPOINTS["create_session"],
                headers=get_headers(jwt),
                json=body,
                timeout=30,
                verify=False
            )
        except requests.RequestException as e:
            raise AccountRequestError(f"创建会话请求失败: {e}")
        
        if resp.status_code != 200:
            JWTManager._handle_error_response(resp, "创建会话")
        
        data = resp.json()
        session_name = data.get("session", {}).get("name")
        logger.info(f"会话创建成功: {session_name}")
        return session_name

# ==================== 消息处理模块 ====================
class MessageProcessor:
    """消息处理器"""
    
    @staticmethod
    def convert_openai_messages(messages: List[Dict]) -> Tuple[str, List[Dict]]:
        """转换OpenAI格式消息为Gemini格式"""
        text_parts = []
        last_user_images = []
        
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            if isinstance(content, str):
                text_parts.append(f"{role}: {content}")
            elif isinstance(content, list):
                msg_text = []
                msg_images = []
                
                for item in content:
                    if isinstance(item, dict):
                        if item.get("type") == "text":
                            msg_text.append(item.get("text", ""))
                        elif item.get("type") == "image_url":
                            img_url = item.get("image_url", {})
                            url = img_url.get("url", "") if isinstance(img_url, dict) else img_url
                            parsed = parse_base64_data_url(url)
                            if parsed:
                                msg_images.append(parsed)
                
                if msg_text:
                    text_parts.append(f"{role}: {' '.join(msg_text)}")
                
                if role == "user" and msg_images:
                    last_user_images = msg_images
        
        return "\n".join(text_parts), last_user_images
    
    @staticmethod
    def build_request_body(
        team_id: str,
        session_name: str,
        message: str,
        model_id: str,
        file_ids: List[str] = None
    ) -> Dict:
        """构建请求体"""
        model_config = CONFIG["models"].get(model_id, CONFIG["models"]["gemini-2.5-flash"])
        base_model = model_config["base"]
        tools = model_config["tools"]
        
        query_parts = [{"text": message}]
        
        body = {
            "configId": team_id,
            "additionalParams": {"token": "-"},
            "streamAssistRequest": {
                "session": session_name,
                "query": {"parts": query_parts},
                "filter": "",
                "fileIds": file_ids or [],
                "answerGenerationMode": "NORMAL",
                "toolsSpec": tools,
                "languageCode": "zh-CN",
                "userMetadata": {"timeZone": "Asia/Shanghai"},
                "assistSkippingMode": "REQUEST_ASSIST",
                "assistGenerationConfig": {"modelId": base_model}
            }
        }
        
        return body

# ==================== 聊天响应数据类 ====================
@dataclass
class ChatResponse:
    """聊天响应"""
    text: str = ""
    image_file_ids: List[Dict] = field(default_factory=list)
    session_path: Optional[str] = None

# ==================== 聊天服务模块 ====================
class ChatService:
    """聊天服务"""
    
    def __init__(self, account_manager: AccountManager):
        self.account_manager = account_manager
    
    def chat(self, messages: List[Dict], model: str, stream: bool = False) -> Tuple[str, str, str]:
        """执行聊天请求"""
        text, images = MessageProcessor.convert_openai_messages(messages)
        
        max_retries = min(CONFIG["max_retries"], len(self.account_manager.accounts))
        max_retries = max(max_retries, 1)
        
        last_error = None
        tried_accounts = set()
        
        for retry in range(max_retries):
            account_idx = None
            try:
                account_idx, account = self.account_manager.get_next_account()
                
                # 避免重复尝试同一账号
                if account_idx in tried_accounts:
                    continue
                tried_accounts.add(account_idx)
                
                logger.info(f"第 {retry + 1} 次尝试，使用账号 {account_idx}")
                
                session, jwt, team_id = self.account_manager.ensure_session(account_idx, account)
                
                # 上传用户图片
                file_ids = []
                for img in images:
                    file_id = FileManager.upload_image(jwt, session, team_id, img)
                    if file_id:
                        file_ids.append(file_id)
                
                # 构建请求体并发送
                body = MessageProcessor.build_request_body(
                    team_id, session, text, model, file_ids
                )
                
                response = self._send_request(jwt, body)
                
                # 构建最终响应内容
                content = self._build_response_content(response, jwt, team_id)
                
                return content, jwt, team_id
                
            except AccountAuthError as e:
                last_error = e
                if account_idx is not None:
                    # 401错误 - 触发刷新
                    if e.status_code == 401:
                        self.account_manager.trigger_refresh(account_idx)
                    else:
                        self.account_manager.set_cooldown(
                            account_idx, str(e), CONFIG["cooldown"]["auth_error"]
                        )
                logger.warning(f"账号 {account_idx} 凭证错误: {e}")
                
            except AccountRateLimitError as e:
                last_error = e
                if account_idx is not None:
                    cooldown = max(CONFIG["cooldown"]["rate_limit"], seconds_until_pt_midnight())
                    self.account_manager.set_cooldown(account_idx, str(e), cooldown)
                logger.warning(f"账号 {account_idx} 触发限流: {e}")
                
            except AccountRequestError as e:
                last_error = e
                if account_idx is not None:
                    self.account_manager.set_cooldown(
                        account_idx, str(e), CONFIG["cooldown"]["generic_error"]
                    )
                logger.warning(f"账号 {account_idx} 请求错误: {e}")
                
            except NoAvailableAccountError as e:
                raise e
                
            except Exception as e:
                last_error = e
                logger.error(f"未知错误: {e}")
                if account_idx is None:
                    break
        
        raise AccountError(f"已重试 {max_retries} 次，全部失败: {last_error}")
    
    def _send_request(self, jwt: str, body: Dict) -> ChatResponse:
        """发送聊天请求"""
        try:
            resp = requests.post(
                API_ENDPOINTS["stream_assist"],
                headers=get_headers(jwt),
                json=body,
                timeout=120,
                verify=False
            )
        except requests.RequestException as e:
            raise AccountRequestError(f"聊天请求失败: {e}")
        
        if resp.status_code == 401:
            raise AccountAuthError("聊天请求认证失败: 401", 401)
        
        if resp.status_code != 200:
            JWTManager._handle_error_response(resp, "聊天请求")
        
        return self._parse_response(resp.text)
    
    def _parse_response(self, response_text: str) -> ChatResponse:
        """解析响应"""
        result = ChatResponse()
        texts = []
        
        try:
            data_list = json.loads(response_text)
            for data in data_list:
                sar = data.get("streamAssistResponse", {})
                
                session_info = sar.get("sessionInfo", {})
                if session_info.get("session"):
                    result.session_path = session_info["session"]
                
                answer = sar.get("answer", {})
                
                for reply in answer.get("replies", []):
                    gc = reply.get("groundedContent", {})
                    content = gc.get("content", {})
                    
                    text = content.get("text", "")
                    thought = content.get("thought", False)
                    
                    if text and not thought:
                        texts.append(text)
                    
                    file_info = content.get("file")
                    if file_info and file_info.get("fileId"):
                        result.image_file_ids.append({
                            "fileId": file_info["fileId"],
                            "mimeType": file_info.get("mimeType", "image/png"),
                            "fileName": file_info.get("name")
                        })
                    
        except json.JSONDecodeError:
            logger.error("响应JSON解析失败")
        
        result.text = "".join(texts)
        return result
    
    def _build_response_content(self, response: ChatResponse, jwt: str, team_id: str) -> str:
        """构建最终响应内容"""
        content = response.text
        
        if not response.image_file_ids or not response.session_path:
            return content
        
        file_metadata = FileManager.get_session_file_metadata(jwt, response.session_path, team_id)
        
        for finfo in response.image_file_ids:
            fid = finfo["fileId"]
            mime_type = finfo["mimeType"]
            fname = finfo.get("fileName")
            
            meta = file_metadata.get(fid)
            if meta:
                fname = fname or meta.get("name")
                session_path = meta.get("session") or response.session_path
            else:
                session_path = response.session_path
            
            image_data = FileManager.download_file(jwt, session_path, fid)
            if image_data:
                b64_data = base64.b64encode(image_data).decode('utf-8')
                content += f"\n\n![Generated Image](data:{mime_type};base64,{b64_data})"
                logger.info(f"图片已添加到响应: {fid}")
            else:
                logger.warning(f"图片下载失败: {fid}")
        
        return content

# ==================== Flask应用 ====================
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# 初始化刷新服务和账号管理器
refresh_service = AccountRefreshService(
    CONFIG["register_service_url"],
    CONFIG["register_admin_key"]
)
account_manager = AccountManager(refresh_service)
chat_service = ChatService(account_manager)

# 启动刷新工作线程
account_manager.start_refresh_worker()

# ==================== 认证装饰器 ====================
def require_admin(f):
    """管理员认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_key = (
            request.headers.get("X-Admin-Key") or
            request.headers.get("Authorization", "").replace("Bearer ", "") or
            request.cookies.get("admin_key")
        )
        if admin_key != CONFIG["admin_key"]:
            return jsonify({"error": "未授权"}), 401
        return f(*args, **kwargs)
    return decorated


def require_api_auth(f):
    """API认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = (
            request.headers.get("Authorization", "").replace("Bearer ", "") or
            request.headers.get("X-API-Key")
        )
        if api_key != CONFIG["admin_key"]:
            return jsonify({"error": "未授权"}), 401
        return f(*args, **kwargs)
    return decorated

# ==================== API路由 ====================
@app.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route('/v1/models', methods=['GET'])
@require_api_auth
def list_models():
    """获取模型列表"""
    models = []
    for model_id in CONFIG["models"].keys():
        models.append({
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google"
        })
    return jsonify({"object": "list", "data": models})


@app.route('/v1/chat/completions', methods=['POST'])
@require_api_auth
def chat_completions():
    """聊天完成接口"""
    try:
        data = request.json
        messages = data.get("messages", [])
        model = data.get("model", "gemini-2.5-flash")
        stream = data.get("stream", False)
        
        if not messages:
            return jsonify({"error": "消息不能为空"}), 400
        
        if model not in CONFIG["models"]:
            model = "gemini-2.5-flash"
        
        content, _, _ = chat_service.chat(messages, model, stream)
        
        if stream:
            def generate():
                chunk_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
                chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {"content": content},
                        "finish_reason": None
                    }]
                }
                yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                
                end_chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                }
                yield f"data: {json.dumps(end_chunk, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"
            
            return Response(generate(), mimetype='text/event-stream')
        else:
            return jsonify({
                "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": len(str(messages)),
                    "completion_tokens": len(content),
                    "total_tokens": len(str(messages)) + len(content)
                }
            })
    
    except NoAvailableAccountError as e:
        return jsonify({"error": str(e)}), 429
    except Exception as e:
        logger.error(f"聊天请求错误: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== 管理API ====================
@app.route('/api/auth/login', methods=['POST'])
def admin_login():
    """管理员登录"""
    data = request.json or {}
    password = data.get("password", "")
    
    if password != CONFIG["admin_key"]:
        return jsonify({"error": "密码错误"}), 401
    
    resp = jsonify({"success": True})
    resp.set_cookie("admin_key", password, max_age=86400, httponly=True, samesite="Lax")
    return resp


@app.route('/api/status', methods=['GET'])
@require_admin
def get_status():
    """获取系统状态"""
    total, available = account_manager.get_available_count()
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "accounts": {"total": total, "available": available},
        "models": list(CONFIG["models"].keys()),
        "config": {
            "account_lifetime": CONFIG["account_lifetime"],
            "refresh_before_expiry": CONFIG["refresh_before_expiry"],
            "refresh_batch_size": CONFIG["refresh_batch_size"],
            "max_retries": CONFIG["max_retries"],
            "register_service_url": CONFIG["register_service_url"],
        }
    })


@app.route('/api/accounts', methods=['GET'])
@require_admin
def get_accounts():
    """获取账号列表"""
    page = request.args.get("page", 1, type=int)
    per_page = 30
    
    accounts = account_manager.get_accounts_json()
    total = len(accounts)
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        "accounts": accounts[start:end],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    })


@app.route('/api/accounts', methods=['POST'])
@require_admin
def add_account():
    """添加账号"""
    data = request.json
    account = {
        "team_id": data.get("team_id", ""),
        "secure_c_ses": data.get("secure_c_ses", ""),
        "host_c_oses": data.get("host_c_oses", ""),
        "csesidx": data.get("csesidx", ""),
        "user_agent": data.get("user_agent", "Mozilla/5.0"),
        "email": data.get("email", ""),
        "available": True,
        "created_at": data.get("created_at") or datetime.now().isoformat(),
        "updated_at": data.get("updated_at") or datetime.now().isoformat(),
    }
    idx = account_manager.add_account(account)
    return jsonify({"success": True, "id": idx})


@app.route('/api/accounts/<int:account_id>', methods=['PUT'])
@require_admin
def update_account(account_id):
    """更新账号"""
    data = request.json
    if account_manager.update_account(account_id, data):
        return jsonify({"success": True})
    return jsonify({"error": "账号不存在"}), 404


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
@require_admin
def delete_account(account_id):
    """删除账号"""
    if account_manager.delete_account(account_id):
        return jsonify({"success": True})
    return jsonify({"error": "账号不存在"}), 404


@app.route('/api/accounts/<int:account_id>/toggle', methods=['POST'])
@require_admin
def toggle_account(account_id):
    """切换账号状态"""
    available = account_manager.toggle_account(account_id)
    return jsonify({"success": True, "available": available})


@app.route('/api/accounts/<int:account_id>/refresh', methods=['POST'])
@require_admin
def refresh_single_account(account_id):
    """刷新单个账号"""
    with account_manager.lock:
        if account_id < 0 or account_id >= len(account_manager.accounts):
            return jsonify({"error": "账号不存在"}), 404
        state = account_manager.states.get(account_id)
        if state and not state.refresh_in_progress:
            state.needs_refresh = True
            account_manager.refresh_queue.put(account_id)
    return jsonify({"success": True, "message": "已加入刷新队列"})


@app.route('/api/accounts/refresh-all', methods=['POST'])
@require_admin
def refresh_all_accounts():
    """刷新所有账号"""
    account_manager.force_refresh_all()
    return jsonify({"success": True, "message": "已将所有账号加入刷新队列"})


@app.route('/api/accounts/<int:account_id>/test', methods=['GET'])
@require_admin
def test_account(account_id):
    """测试账号"""
    with account_manager.lock:
        if account_id < 0 or account_id >= len(account_manager.accounts):
            return jsonify({"success": False, "message": "账号不存在"}), 404
        account = account_manager.accounts[account_id]
    
    try:
        jwt = JWTManager.fetch_jwt(account)
        return jsonify({"success": True, "message": "JWT获取成功"})
    except AccountError as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/api/accounts/import', methods=['POST'])
@require_admin
def import_accounts():
    """导入账号配置（支持时间戳）"""
    data = request.json
    accounts = data.get("accounts", [])
    if not isinstance(accounts, list):
        return jsonify({"error": "无效的账号数据"}), 400
    
    # 处理导入的账号，添加时间戳
    processed_accounts = []
    for acc in accounts:
        processed = {
            "team_id": acc.get("team_id", ""),
            "secure_c_ses": acc.get("secure_c_ses", ""),
            "host_c_oses": acc.get("host_c_oses", ""),
            "csesidx": acc.get("csesidx", ""),
            "user_agent": acc.get("user_agent", "Mozilla/5.0"),
            "email": acc.get("email", ""),
            "available": acc.get("available", True),
            "created_at": acc.get("created_at") or datetime.now().isoformat(),
            "updated_at": acc.get("updated_at") or acc.get("created_at") or datetime.now().isoformat(),
        }
        processed_accounts.append(processed)
    
    account_manager.load_accounts(processed_accounts)
    return jsonify({"success": True, "count": len(processed_accounts)})


@app.route('/api/accounts/export', methods=['GET'])
@require_admin
def export_accounts():
    """导出账号配置"""
    with account_manager.lock:
        accounts = []
        for i, acc in enumerate(account_manager.accounts):
            state = account_manager.states.get(i, AccountState())
            accounts.append({
                **acc,
                "created_at": state.created_at.isoformat() if state.created_at else acc.get("created_at", ""),
                "updated_at": state.updated_at.isoformat() if state.updated_at else acc.get("updated_at", ""),
            })
    return jsonify({"accounts": accounts})


@app.route('/api/config', methods=['GET'])
@require_admin
def get_config():
    """获取配置"""
    return jsonify({
        "account_lifetime": CONFIG["account_lifetime"],
        "refresh_before_expiry": CONFIG["refresh_before_expiry"],
        "refresh_batch_size": CONFIG["refresh_batch_size"],
        "max_retries": CONFIG["max_retries"],
        "register_service_url": CONFIG["register_service_url"],
    })


@app.route('/api/config', methods=['PUT'])
@require_admin
def update_config():
    """更新配置"""
    data = request.json
    
    if "account_lifetime" in data:
        CONFIG["account_lifetime"] = int(data["account_lifetime"])
    if "refresh_before_expiry" in data:
        CONFIG["refresh_before_expiry"] = int(data["refresh_before_expiry"])
    if "refresh_batch_size" in data:
        CONFIG["refresh_batch_size"] = int(data["refresh_batch_size"])
    if "max_retries" in data:
        CONFIG["max_retries"] = int(data["max_retries"])
    if "register_service_url" in data:
        CONFIG["register_service_url"] = data["register_service_url"]
        refresh_service.base_url = data["register_service_url"].rstrip('/')
    
    return jsonify({"success": True})


@app.route('/')
def index():
    """管理面板首页"""
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "index.html not found", 404


# ==================== 启动 ====================
def main():
    """启动服务"""
    logger.info("=" * 60)
    logger.info("Business Gemini OpenAPI 服务启动")
    logger.info("=" * 60)
    logger.info(f"管理员密钥: {CONFIG['admin_key'][:4]}****")
    logger.info(f"注册服务URL: {CONFIG['register_service_url']}")
    logger.info(f"账号生命周期: {CONFIG['account_lifetime']} 秒")
    logger.info(f"提前刷新时间: {CONFIG['refresh_before_expiry']} 秒")
    logger.info(f"刷新批量大小: {CONFIG['refresh_batch_size']}")
    logger.info(f"最大重试次数: {CONFIG['max_retries']}")
    logger.info(f"支持模型: {', '.join(CONFIG['models'].keys())}")
    logger.info("=" * 60)
    logger.info("API端点:")
    logger.info("  GET  /health              - 健康检查")
    logger.info("  GET  /v1/models           - 模型列表")
    logger.info("  POST /v1/chat/completions - 聊天接口")
    logger.info("  GET  /                    - 管理面板")
    logger.info("=" * 60)
    
    app.run(host='0.0.0.0', port=8000, debug=False)


if __name__ == '__main__':
    main()
