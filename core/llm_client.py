"""
LLM客户端
提供大模型调用能力，用于LLM-as-a-Judge审查
"""
import os
import json
import time
import requests
from typing import Dict, Optional
from core.config_loader import ConfigLoader


class LLMClient:
    """LLM客户端"""
    
    def __init__(self, config: ConfigLoader = None):
        self.config = config or ConfigLoader()
        self.llm_config = self.config.llm_config
    
    def call_llm(self, system_prompt: str, user_prompt: str, model: str = None, max_tokens: int = 4096, max_retries: int = 3) -> Optional[str]:
        """调用大模型（带重试机制）
        
        Args:
            system_prompt: 系统提示词（角色定义）
            user_prompt: 用户提示词（审查内容）
            model: 模型名称
            max_tokens: 最大输出token数
            max_retries: 最大重试次数（默认3次）
        
        Returns:
            模型响应文本
        """
        config = self.llm_config
        if not config or not config.get('api_key'):
            print("  [错误] LLM配置未完成，无法调用审查")
            return None
        
        model_name = model or config.get('model', 'glm-4-flash')
        api_url = config.get('api_url', 'https://open.bigmodel.cn/api/paas/v4/chat/completions')
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['api_key']}"
        }
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        payload = {
            "model": model_name,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.0
        }
        
        last_exception = None
        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(api_url, headers=headers, json=payload, timeout=180)
                if response.status_code == 200:
                    result = response.json()
                    if result.get('choices'):
                        content = result['choices'][0]['message'].get('content') or ""
                        if content.strip():
                            return content
                        print(f"  [错误] LLM响应无内容: {result}")
                        return None
                    else:
                        print(f"  [错误] LLM响应无内容: {result}")
                        return None
                else:
                    print(f"  [错误] LLM调用失败: HTTP {response.status_code}, {response.text[:200]}")
                    return None
            except requests.exceptions.SSLError as e:
                last_exception = e
                print(f"  [警告] LLM调用SSL错误（第{attempt}/{max_retries}次）: {str(e)[:100]}")
                if attempt < max_retries:
                    wait_time = 2 ** attempt  # 指数退避：2, 4, 8秒
                    print(f"  [重试] {wait_time}秒后重试...")
                    time.sleep(wait_time)
                continue
            except requests.exceptions.Timeout as e:
                last_exception = e
                print(f"  [警告] LLM调用超时（第{attempt}/{max_retries}次）")
                if attempt < max_retries:
                    wait_time = 2 ** attempt
                    print(f"  [重试] {wait_time}秒后重试...")
                    time.sleep(wait_time)
                continue
            except Exception as e:
                print(f"  [错误] LLM调用异常: {e}")
                return None
        
        # 所有重试都失败
        print(f"  [错误] LLM调用在{max_retries}次重试后仍然失败: {last_exception}")
        return None
