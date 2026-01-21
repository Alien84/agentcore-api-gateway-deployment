#!/usr/bin/env python3
"""
Test script for AgentCore API key authentication
"""
import boto3
import json
import uuid
from datetime import datetime


# Configuration
AGENT_ARN = "arn:aws:bedrock-agentcore:us-east-1:620584312149:runtime/langgraph_agent-btnmiJ4tGm"
REGION = "us-east-1"
VALID_API_KEY = "eJnm7mrV4ZpO10JFNA0Wj87MxBj0PYUixYt2xKRQBu4"
INVALID_API_KEY = "invalid-key-12345"

def invoke_agent(api_key: str, prompt: str = "Hello, test authentication"):
    """
    Invoke the AgentCore agent with API key authentication.

    This uses boto3 to handle AWS SigV4 authentication, and includes
    the custom Authorization header for your API key validation.
    """
    client = boto3.client('bedrock-agentcore-runtime', region_name=REGION)

    try:
        # Prepare the payload
        payload = {
            "prompt": prompt,
            "actor_id": "test-user",
            "thread_id": f"test-session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        }

        # Prepare custom headers (including Authorization header with API key)
        custom_headers = {
            "Authorization": f"Bearer {api_key}",
            "X-Amzn-Bedrock-AgentCore-Runtime-Request-Id": str(uuid.uuid4())
        }

        print(f"\n{'='*60}")
        print(f"Testing with API Key: {api_key[:10]}...")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        print(f"{'='*60}\n")

        # Invoke the agent
        # Note: The AgentCore SDK will handle AWS SigV4 authentication
        # Our custom headers will be passed through to the agent code
        response = client.invoke_agent_runtime(
            agentRuntimeArn=AGENT_ARN,
            payload=json.dumps(payload),
            # Custom headers are passed here
            # However, boto3's bedrock-agentcore-runtime client may not support
            # custom headers directly. We might need to use requests with AWS auth.
        )

        # Parse response
        result = json.loads(response['payload'])

        print("✅ SUCCESS!")
        print(f"Status Code: {response['ResponseMetadata']['HTTPStatusCode']}")
        print(f"Response: {json.dumps(result, indent=2)}")

        return True, result

    except Exception as e:
        print(f"❌ FAILED!")
        print(f"Error: {str(e)}")
        print(f"Error Type: {type(e).__name__}")
        return False, str(e)


def test_with_requests():
    """
    Test using direct HTTP requests (like the AWS sample code).
    No AWS SigV4 needed - just Bearer token authentication!
    """
    import requests
    import urllib.parse

    # Construct the endpoint URL (URL-encode the ARN)
    escaped_arn = urllib.parse.quote(AGENT_ARN, safe="")
    endpoint_url = f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/{escaped_arn}/invocations"

    def test_request(api_key: str, prompt: str = "Test authentication"):
        # Prepare payload
        payload = {
            "prompt": prompt,
            "actor_id": "test-user",
            "thread_id": f"test-session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        }

        # Prepare headers (like AWS sample code)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": str(uuid.uuid4()),
            "X-Amzn-Bedrock-AgentCore-Runtime-Request-Id": str(uuid.uuid4())
        }

        print(f"\n{'='*60}")
        print(f"Testing with API Key: {api_key[:10] if api_key else '(empty)'}...")
        print(f"Endpoint: {endpoint_url}")
        print(f"Payload: {json.dumps(payload)}")
        print(f"{'='*60}\n")

        try:
            # Make HTTP request with qualifier parameter (CRITICAL!)
            response = requests.post(
                endpoint_url,
                params={"qualifier": "DEFAULT"},  # This was missing!
                headers=headers,
                json=payload,
                timeout=100
            )

            print(f"Status Code: {response.status_code}")

            if response.status_code == 200:
                print("✅ SUCCESS!")
                try:
                    print(f"Response: {response.json()}")
                except:
                    print(f"Response (text): {response.text}")
                return True
            elif response.status_code == 401:
                print("❌ UNAUTHORIZED (Expected for invalid/missing API key)")
                print(f"Response: {response.text}")
                return False
            else:
                print(f"❌ FAILED with status {response.status_code}")
                print(f"Response: {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"❌ REQUEST FAILED!")
            print(f"Error: {str(e)}")
            return False

    return test_request


if __name__ == "__main__":
    print("=" * 60)
    print("AgentCore API Key Authentication Test")
    print("=" * 60)

    # Test using requests library with SigV4 signing
    print("\n🔍 Testing authentication with requests + SigV4...")

    try:
        test_request = test_with_requests()

        # Test 1: Valid API Key
        print("\n\n📝 Test 1: Valid API Key")
        print("-" * 60)
        success1 = test_request(VALID_API_KEY, "Explain roaming activation")

        # Test 2: Invalid API Key (should return 401)
        print("\n\n📝 Test 2: Invalid API Key (should fail with 401)")
        print("-" * 60)
        success2 = test_request(INVALID_API_KEY, "This should be rejected")

        # Test 3: No API Key (should return 401)
        print("\n\n📝 Test 3: No API Key (should fail with 401)")
        print("-" * 60)
        success3 = test_request("", "This should also be rejected")

        # Summary
        print("\n\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Test 1 (Valid API Key): {'PASSED' if success1 else 'FAILED'}")
        print(f"❌ Test 2 (Invalid API Key): {'PASSED (correctly rejected)' if not success2 else 'FAILED (should have been rejected!)'}")
        print(f"❌ Test 3 (No API Key): {'PASSED (correctly rejected)' if not success3 else 'FAILED (should have been rejected!)'}")

    except ImportError:
        print("\n❌ Error: 'requests' library not found.")
        print("Install it with: pip install requests")
        print("\nAlternatively, install with uv:")
        print("uv pip install requests")