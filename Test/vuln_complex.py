"""
Complex vulnerability test file - requires data flow analysis to detect.
Vulnerabilities are not obvious from single function inspection;
they require tracking user input through multiple functions and layers.
"""

import subprocess
import hashlib
import hmac
import base64
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class UserRequest:
    """Represents an incoming user request."""
    user_id: str
    action: str
    payload: Dict[str, Any]
    metadata: Dict[str, str]


class ConfigManager:
    """Manages application configuration."""
    
    def __init__(self):
        self._config = {
            "allowed_commands": ["list", "status", "info"],
            "max_payload_size": 1024,
            "secret_salt": "static_salt_value",  # Weak: hardcoded salt
        }
    
    def get_allowed_commands(self) -> list:
        return self._config["allowed_commands"]
    
    def get_secret_salt(self) -> str:
        return self._config["secret_salt"]


class InputValidator:
    """Validates and sanitizes user input."""
    
    def __init__(self, config: ConfigManager):
        self.config = config
    
    def validate_action(self, action: str) -> bool:
        """Check if action is in allowed list."""
        return action in self.config.get_allowed_commands()
    
    def sanitize_string(self, value: str) -> str:
        """Basic sanitization - removes some dangerous chars but incomplete."""
        # Incomplete sanitization - misses many bypasses
        dangerous = [";", "&", "|", "`", "$", "(", ")", "<", ">"]
        for char in dangerous:
            value = value.replace(char, "")
        return value
    
    def validate_payload_size(self, payload: Dict[str, Any]) -> bool:
        """Check payload size limit."""
        import json
        return len(json.dumps(payload)) <= self.config._config["max_payload_size"]


class CommandBuilder:
    """Builds system commands from user input - VULNERABLE TO COMMAND INJECTION."""
    
    def __init__(self, validator: InputValidator):
        self.validator = validator
    
    def build_list_command(self, target: str, options: Dict[str, str]) -> list:
        """
        Build a command to list resources.
        VULNERABILITY: target and options values flow into command without proper validation.
        The sanitize_string() is incomplete and can be bypassed.
        """
        # User-controlled 'target' goes through sanitize_string but it's insufficient
        sanitized_target = self.validator.sanitize_string(target)
        
        # Options values also user-controlled
        sanitized_options = {}
        for key, value in options.items():
            sanitized_options[key] = self.validator.sanitize_string(value)
        
        # Command built with user input - injection possible via:
        # - Newlines in target/options (not filtered)
        # - Command substitution $() or backticks (not filtered)
        # - Argument injection via --flags
        cmd = ["resource_tool", "list", sanitized_target]
        
        for key, value in sanitized_options.items():
            cmd.extend([f"--{key}", value])
        
        return cmd
    
    def build_status_command(self, resource_id: str, format_type: str) -> list:
        """Build status check command."""
        sanitized_id = self.validator.sanitize_string(resource_id)
        sanitized_format = self.validator.sanitize_string(format_type)
        
        # VULNERABILITY: format_type used directly in command
        # Can inject: "json; malicious_command"
        return ["resource_tool", "status", sanitized_id, "--format", sanitized_format]


class CommandExecutor:
    """Executes system commands."""
    
    def __init__(self):
        self.execution_log = []
    
    def execute(self, command: list, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a command.
        VULNERABILITY: Uses shell=True indirectly via subprocess with list but
        if command elements contain shell metacharacters, issues can occur.
        More critically, the command list itself is built from user input.
        """
        try:
            # The command list comes from CommandBuilder which uses user input
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                # shell=False is default but list can still be problematic
                # if arguments contain shell metacharacters interpreted by the binary
            )
            
            self.execution_log.append({
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:500]
            })
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class AuthTokenGenerator:
    """Generates authentication tokens - VULNERABLE: weak crypto implementation."""
    
    def __init__(self, config: ConfigManager):
        self.config = config
    
    def generate_token(self, user_id: str, action: str, timestamp: int) -> str:
        """
        Generate HMAC token for request authentication.
        VULNERABILITIES:
        1. Uses hardcoded static salt (from config)
        2. Uses SHA1 (weak hash algorithm)
        3. Token includes user_id and action in plaintext
        4. No token expiration validation shown
        """
        # Weak: static salt from config
        secret = self.config.get_secret_salt()
        
        # Weak: SHA1 is cryptographically broken
        message = f"{user_id}:{action}:{timestamp}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha1  # VULNERABILITY: SHA1
        ).digest()
        
        token = base64.b64encode(signature).decode()
        return f"{user_id}:{action}:{timestamp}:{token}"
    
    def verify_token(self, token: str, max_age: int = 3600) -> Optional[Dict[str, Any]]:
        """
        Verify authentication token.
        VULNERABILITY: Timing attack possible in string comparison.
        Also doesn't properly validate timestamp freshness in all paths.
        """
        try:
            parts = token.split(":")
            if len(parts) != 4:
                return None
            
            user_id, action, timestamp_str, provided_sig = parts
            timestamp = int(timestamp_str)
            
            # Check expiration
            import time
            if time.time() - timestamp > max_age:
                return None
            
            # Regenerate expected signature
            expected_token = self.generate_token(user_id, action, timestamp)
            expected_sig = expected_token.split(":")[3]
            
            # VULNERABILITY: Timing attack - string comparison not constant-time
            if provided_sig == expected_sig:
                return {"user_id": user_id, "action": action, "timestamp": timestamp}
            
            return None
        except (ValueError, IndexError):
            return None


class RequestProcessor:
    """Main request processing logic - orchestrates the vulnerable flow."""
    
    def __init__(self):
        self.config = ConfigManager()
        self.validator = InputValidator(self.config)
        self.builder = CommandBuilder(self.validator)
        self.executor = CommandExecutor()
        self.auth = AuthTokenGenerator(self.config)
    
    def process_request(self, request: UserRequest) -> Dict[str, Any]:
        """
        Process a user request.
        COMPLEX VULNERABILITY CHAIN:
        1. User input enters via request.payload
        2. Passes through validator (incomplete sanitization)
        3. Flows into CommandBuilder (builds command with user data)
        4. Executed by CommandExecutor (runs system command)
        5. Auth token uses weak crypto (SHA1, static salt, timing attack)
        
        Detection requires:
        - Taint tracking from request.payload through validator -> builder -> executor
        - Understanding that sanitize_string() is incomplete
        - Recognizing crypto weaknesses in AuthTokenGenerator
        """
        # Step 1: Validate action
        if not self.validator.validate_action(request.action):
            return {"success": False, "error": "Invalid action"}
        
        # Step 2: Validate payload size
        if not self.validator.validate_payload_size(request.payload):
            return {"success": False, "error": "Payload too large"}
        
        # Step 3: Verify auth token (if provided)
        auth_token = request.metadata.get("auth_token")
        if auth_token:
            auth_result = self.auth.verify_token(auth_token)
            if not auth_result:
                return {"success": False, "error": "Invalid or expired token"}
            if auth_result["user_id"] != request.user_id:
                return {"success": False, "error": "Token user mismatch"}
        
        # Step 4: Build and execute command based on action
        if request.action == "list":
            target = request.payload.get("target", "default")
            options = request.payload.get("options", {})
            
            # VULNERABLE: user-controlled target and options flow into command
            command = self.builder.build_list_command(target, options)
            
        elif request.action == "status":
            resource_id = request.payload.get("resource_id", "")
            format_type = request.payload.get("format", "json")
            
            # VULNERABLE: user-controlled resource_id and format flow into command
            command = self.builder.build_status_command(resource_id, format_type)
            
        else:
            return {"success": False, "error": "Unknown action"}
        
        # Step 5: Execute the command (sink)
        result = self.executor.execute(command)
        
        return {
            "success": result["success"],
            "data": result.get("output"),
            "error": result.get("error")
        }


# Example usage demonstrating the vulnerability chain
def demonstrate_vulnerability():
    """Show how user input flows through the system to command execution."""
    processor = RequestProcessor()
    
    # This request would trigger command injection if resource_tool exists
    # and accepts the injected arguments
    malicious_request = UserRequest(
        user_id="attacker",
        action="list",
        payload={
            "target": "legitimate_target\n; malicious_command #",  # Newline injection
            "options": {
                "filter": "name; cat /etc/passwd",  # Semicolon injection (partially filtered)
                "sort": "`id`"  # Backtick injection (not filtered)
            }
        },
        metadata={
            "auth_token": "attacker:list:1234567890:fakesignature"
        }
    )
    
    # The vulnerability chain:
    # malicious_request.payload -> validator.sanitize_string() [INCOMPLETE]
    # -> CommandBuilder.build_list_command() -> CommandExecutor.execute()
    # -> subprocess.run() with user-controlled arguments
    
    result = processor.process_request(malicious_request)
    return result


if __name__ == "__main__":
    print("Complex vulnerability demonstration:")
    print(demonstrate_vulnerability())