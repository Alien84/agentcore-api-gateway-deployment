# Complete AgentCore Deployment Guide: From Development to Production

> **Document Purpose**: This comprehensive guide covers the complete workflow from building an AgentCore agent to exposing it via API Gateway for third-party server access.
>
> **Target Audience**: Developers who want to deploy an AI agent on AWS and make it accessible to external applications
>
> **What You'll Build**:
> - A LangGraph-based FAQ agent with RAG capabilities
> - Fully managed AgentCore runtime on AWS
> - API Gateway with API key authentication
> - Lambda proxy for AWS SigV4 authentication
>
> **End Result**: A production-ready HTTP endpoint that third-party servers can call with simple API key authentication

---

## Table of Contents

1. [Prerequisites and Setup](#prerequisites-and-setup)
2. [Part 1: Building and Deploying AgentCore Runtime](#part-1-building-and-deploying-agentcore-runtime)
3. [Part 2: Building API Gateway Infrastructure](#part-2-building-api-gateway-infrastructure)
4. [Part 3: Testing and Validation](#part-3-testing-and-validation)
5. [Part 4: Third-Party Integration](#part-4-third-party-integration)
6. [Part 5: Troubleshooting](#part-5-troubleshooting)
7. [Part 6: Maintenance and Updates](#part-6-maintenance-and-updates)

---

## Architecture Overview

### ❌ What DOESN'T Work: Direct HTTP Integration

We initially tried API Gateway → HTTP Integration → AgentCore, but this fails because:
- HTTP integration doesn't automatically add AWS SigV4 authentication
- AgentCore requires SigV4 or OAuth - it rejects simple Bearer tokens
- Error: "Authorization method mismatch"

### ✅ What WORKS: API Gateway + Lambda Proxy

```
┌─────────────────────────┐
│ Third-Party Server      │
│ (Azure/GCP/etc.)        │
└───────────┬─────────────┘
            │ HTTP POST
            │ x-api-key: <api_key>
            │ {"prompt": "..."}
            ↓
┌───────────────────────────────────────────┐
│ AWS API Gateway                           │
│ ✅ Validates API key                      │
│ ✅ Rate limiting (50 req/s, 10K/day)      │
│ ✅ Returns 403 if invalid/missing key     │
└───────────┬───────────────────────────────┘
            │ Invokes Lambda (AWS_PROXY)
            │ Passes full request event
            ↓
┌───────────────────────────────────────────┐
│ AWS Lambda (AgentCoreProxy)               │
│ ✅ Extracts prompt from request body      │
│ ✅ Adds AWS SigV4 authentication          │
│ ✅ Uses boto3 + SigV4Auth                 │
└───────────┬───────────────────────────────┘
            │ HTTP POST with SigV4
            │ Authorization: AWS4-HMAC-SHA256...
            │ {"prompt": "...", "actor_id": "...", "thread_id": "..."}
            ↓
┌───────────────────────────────────────────┐
│ Amazon Bedrock AgentCore                  │
│ ✅ Validates SigV4 signature              │
│ ✅ Checks IAM permissions                 │
│ ✅ Routes to agent container              │
└───────────┬───────────────────────────────┘
            │
            ↓
┌───────────────────────────────────────────┐
│ Your LangGraph Agent                      │
│ • Searches FAQ knowledge base (FAISS)     │
│ • Uses Groq LLM for responses             │
│ • Returns structured answer               │
└───────────┬───────────────────────────────┘
            │
            │ {"result": "answer"}
            ↓
         Returns to third-party
```

**Key Benefits**:
- ✅ Third-party uses simple API key (no AWS credentials needed)
- ✅ Lambda handles complex SigV4 signing automatically
- ✅ AgentCore gets properly authenticated requests
- ✅ Rate limiting and monitoring built-in
- ✅ Production-ready security

---

## Why API Gateway + Lambda is Required

### The Core Problem

**AgentCore's security model enforces**:
1. **AWS SigV4 Authentication** (for AWS SDK clients)
2. **OAuth/JWT Authentication** (for configured OAuth providers)

**There is NO "simple API key" mode** at the AgentCore infrastructure level.

### What We Tried (and Why It Failed)

#### ❌ Attempt 1: Custom validation in agent code
```python
# In 01_agentcore_runtime.py (DOESN'T WORK)
auth_header = request_headers.get("Authorization", "")
if auth_header.startswith("Bearer "):
    # This code never executes for external HTTP requests
    # because AgentCore blocks them before reaching your code
```
**Result**: 403 "Authorization method mismatch" - request blocked at infrastructure layer

#### ❌ Attempt 2: HTTP Integration with credentials
```bash
# API Gateway HTTP integration with IAM role (DOESN'T WORK)
aws apigateway put-integration \
  --type HTTP \
  --credentials "arn:aws:iam::ACCOUNT:role/Role" \
  --uri "https://bedrock-agentcore.../invocations"
```
**Result**: HTTP integration doesn't add SigV4 headers, so AgentCore still rejects requests

#### ❌ Attempt 3: AWS Integration type
```bash
# API Gateway AWS integration (DOESN'T WORK)
aws apigateway put-integration \
  --type AWS \
  --uri "https://bedrock-agentcore.../invocations"
```
**Result**: "Invalid ARN specified" - bedrock-agentcore not in supported AWS services list

### ✅ The Solution: Lambda Proxy

**Why Lambda works**:
1. Lambda can use boto3's `SigV4Auth` to sign requests
2. API Gateway invokes Lambda with full request context
3. Lambda extracts API key validation status from API Gateway
4. Lambda adds SigV4 to AgentCore requests
5. AgentCore accepts SigV4-signed requests

**This is the AWS-recommended pattern** for integrating with custom AWS services that require SigV4 but aren't directly supported by API Gateway.

---

## Prerequisites and Setup

### Required Tools and Accounts

**1. AWS Account**
- Active AWS account with billing enabled
- IAM user with administrator access (or specific permissions for Bedrock, Lambda, API Gateway, IAM)
- AWS region: `us-east-1` (recommended for AgentCore availability)

**2. AWS CLI**
```bash
# Install AWS CLI v2 (macOS example)
brew install awscli

# Or download from: https://aws.amazon.com/cli/

# Verify installation
aws --version
# Should show: aws-cli/2.x.x or higher
```

**3. Configure AWS Credentials**
```bash
# Run AWS configure
aws configure

# Enter your credentials:
# AWS Access Key ID: YOUR_ACCESS_KEY
# AWS Secret Access Key: YOUR_SECRET_KEY
# Default region name: us-east-1
# Default output format: json

# Verify configuration
aws sts get-caller-identity
# Should return your account ID and ARN
```

**4. Python Environment**
```bash
# Install uv (modern Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or use pip
pip install uv

# Verify installation
uv --version
```

**5. Install AgentCore CLI**
```bash
# Install bedrock-agentcore-starter-toolkit
uv pip install bedrock-agentcore-starter-toolkit

# Or if using regular pip
pip install bedrock-agentcore-starter-toolkit

# Verify installation
agentcore --version
```

**6. Get Groq API Key** (for LLM access)
1. Go to https://console.groq.com/
2. Sign up for a free account
3. Navigate to API Keys section
4. Create a new API key
5. Copy the key (you'll need it later)

### Project Setup

**1. Clone or Set Up Project Directory**
```bash
# Navigate to your project directory
cd /path/to/your/project

# Or create a new one
mkdir my-agentcore-project
cd my-agentcore-project
```

**2. Create Python Environment**
```bash
# Initialize uv project
uv sync

# This creates a virtual environment and installs dependencies
# from pyproject.toml (if exists)
```

**3. Create `.env` File**
```bash
# Create .env file for API keys
cat > .env << 'EOF'
GROQ_API_KEY=your_groq_api_key_here
EOF

# Load environment variables
source .env  # On macOS/Linux
# or
set -a; source .env; set +a  # Alternative
```

**4. Verify Prerequisites**
```bash
# Check AWS access
aws sts get-caller-identity

# Check Python
python --version  # Should be 3.10+

# Check AgentCore CLI
agentcore --version

# Check environment variables
echo $GROQ_API_KEY  # Should show your key
```

---

## Part 1: Building and Deploying AgentCore Runtime

### Step 1.1: Understanding the Agent Architecture

Your agent will use:
- **LangGraph**: Framework for building stateful agent applications
- **LangChain**: For LLM orchestration and tool integration
- **FAISS**: Vector database for FAQ retrieval (in-memory)
- **Groq LLM**: Fast inference with `openai/gpt-oss-20b` model
- **AgentCore**: AWS managed runtime for deployment

**Architecture**:
```
User Query → AgentCore Runtime → LangGraph Agent → Tools (FAQ Search) → LLM → Response
```

### Step 1.2: Prepare FAQ Data

Ensure you have `lauki_qna.csv` in your project directory. This contains the knowledge base for the agent.

**Check the file**:
```bash
ls -lh lauki_qna.csv
head -n 5 lauki_qna.csv
```

**Expected format**:
```csv
question,answer
"How do I activate roaming?","To activate roaming, dial *123# and select..."
"What are the data plans?","Our data plans include..."
```

### Step 1.3: Create the Agent Code

**File**: `01_agentcore_runtime.py`

```python
import os
from typing import Annotated

from bedrock_agentcore import BedrockAgentCoreApp
from langchain_groq import ChatGroq
from langchain_community.document_loaders.csv_loader import CSVLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langgraph.graph import StateGraph, MessagesState, START
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_core.tools import tool

# Initialize BedrockAgentCoreApp
app = BedrockAgentCoreApp()

# Load FAQ data from CSV
loader = CSVLoader(
    file_path="lauki_qna.csv",
    encoding="utf-8",
    csv_args={"delimiter": ","}
)
data = loader.load()

# Split text into chunks
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=0
)
docs = text_splitter.split_documents(data)

# Create embeddings and vector store
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)
vectordb = FAISS.from_documents(docs, embeddings)

# Define tools for FAQ search
@tool
def search_faq(query: Annotated[str, "The search query to find relevant FAQs"]) -> str:
    """Search the FAQ knowledge base for relevant information."""
    results = vectordb.similarity_search(query, k=3)
    return "\n\n".join([doc.page_content for doc in results])

@tool
def search_detailed_faq(
    query: Annotated[str, "The search query"],
    num_results: Annotated[int, "Number of results to return"] = 5
) -> str:
    """Search the FAQ knowledge base with more comprehensive results."""
    results = vectordb.similarity_search(query, k=num_results)
    return "\n\n".join([doc.page_content for doc in results])

@tool
def reformulate_query(
    original_query: Annotated[str, "The original user query"],
    focus_aspect: Annotated[str, "The specific aspect to focus on"]
) -> str:
    """Reformulate the query with a specific focus and search the FAQ."""
    reformulated = f"{original_query} {focus_aspect}"
    results = vectordb.similarity_search(reformulated, k=3)
    return "\n\n".join([doc.page_content for doc in results])

# Initialize LLM
tools = [search_faq, search_detailed_faq, reformulate_query]
llm = ChatGroq(
    api_key=os.environ["GROQ_API_KEY"],
    model="openai/gpt-oss-20b",
    temperature=0
)
llm_with_tools = llm.bind_tools(tools)

# Define system prompt
sys_msg = """You are a helpful customer service agent for Lauki, a telecommunications company.
Your role is to answer questions about Lauki's services using the FAQ knowledge base.

Guidelines:
1. Always search the FAQ database before answering
2. If information is not in the FAQ, say so politely
3. Be concise but complete in your answers
4. Use multiple search strategies if the first search doesn't yield good results
5. Format your responses clearly with bullet points when appropriate

Remember: You have access to search_faq, search_detailed_faq, and reformulate_query tools."""

# Define agent logic
def assistant(state: MessagesState):
    return {"messages": [llm_with_tools.invoke([{"role": "system", "content": sys_msg}] + state["messages"])]}

# Build agent graph
builder = StateGraph(MessagesState)
builder.add_node("assistant", assistant)
builder.add_node("tools", ToolNode(tools))
builder.add_edge(START, "assistant")
builder.add_conditional_edges("assistant", tools_condition)
builder.add_edge("tools", "assistant")
agent = builder.compile()

# Define AgentCore entrypoint
@app.entrypoint
def agent_invocation(payload, context):
    """
    AgentCore entrypoint for agent invocations.

    Args:
        payload (dict): Request payload with structure:
            {
                "prompt": "user question",
                "actor_id": "optional-user-id",
                "thread_id": "optional-session-id"
            }
        context: AgentCore runtime context

    Returns:
        dict: Response with structure:
            {
                "result": "agent response text",
                "actor_id": "user-id",
                "thread_id": "session-id"
            }
    """
    print("Received payload:", payload)
    print("Context:", context)

    # Extract query from payload
    query = payload.get("prompt", "No prompt found in input")
    actor_id = payload.get("actor_id", "default-user")
    thread_id = payload.get("thread_id", "default-session")

    # Invoke agent
    result = agent.invoke({"messages": [("human", query)]})

    # Extract response
    response_text = result['messages'][-1].content

    # Return formatted response
    return {
        "result": response_text,
        "actor_id": actor_id,
        "thread_id": thread_id
    }
```

**Save the file** and verify syntax:
```bash
python -c "import py_compile; py_compile.compile('01_agentcore_runtime.py', doraise=True)"
# Should return nothing if successful
```

### Step 1.4: Test Agent Locally (Optional but Recommended)

Before deploying to AgentCore, test the agent locally:

```bash
# Activate virtual environment
source .venv/bin/activate

# Test the agent locally
python << 'EOF'
from 01_agentcore_runtime import agent

# Test invocation
result = agent.invoke({"messages": [("human", "How do I activate roaming?")]})
print("Response:", result['messages'][-1].content)
EOF
```

### Step 1.5: Configure AgentCore

```bash
# Configure AgentCore with your agent file
agentcore configure -e 01_agentcore_runtime.py

# This generates .bedrock_agentcore.yaml
```

**What this does**:
1. Creates `.bedrock_agentcore.yaml` configuration file
2. Registers your agent with AgentCore
3. Sets up AWS resources (ECR repository, IAM roles)
4. Configures network settings (PUBLIC mode by default)

**Verify configuration**:
```bash
cat .bedrock_agentcore.yaml
```

**Key fields to review**:
```yaml
agent_id: langgraph_agent-XXXXX
entrypoint: 01_agentcore_runtime.py
region: us-east-1
aws:
  network_configuration:
    network_mode: PUBLIC  # Agent accessible from internet
  protocol_configuration:
    server_protocol: HTTP  # HTTP protocol (TLS handled by AWS)
```

### Step 1.6: Deploy Agent to AgentCore

```bash
# Deploy agent with environment variables
agentcore launch --env GROQ_API_KEY=$GROQ_API_KEY

# This will:
# 1. Build Docker container with your agent code
# 2. Push container to ECR
# 3. Deploy to AgentCore runtime
# 4. Start the agent service

# Wait for deployment (2-5 minutes)
```

**Monitor deployment**:
```bash
# Check deployment status
agentcore status

# Expected output:
# Agent Status: RUNNING
# Agent ID: langgraph_agent-XXXXX
# Runtime ARN: arn:aws:bedrock-agentcore:us-east-1:ACCOUNT_ID:runtime/langgraph_agent-XXXXX
```

### Step 1.7: Test Deployed Agent

```bash
# Test with agentcore CLI
agentcore invoke '{"prompt": "Explain roaming activation"}'

# Expected output:
# {
#   "result": "To activate roaming, you need to...",
#   "actor_id": "default-user",
#   "thread_id": "default-session"
# }
```

**Troubleshooting deployment issues**:

**Error: "Docker daemon not running"**
```bash
# Start Docker Desktop (macOS)
open -a Docker

# Or install Docker: https://www.docker.com/products/docker-desktop
```

**Error: "AWS credentials not found"**
```bash
# Reconfigure AWS CLI
aws configure

# Verify credentials
aws sts get-caller-identity
```

**Error: "Permission denied" during deployment**
```bash
# Check IAM permissions
# Your IAM user needs:
# - bedrock-agentcore:*
# - ecr:*
# - iam:CreateRole, iam:AttachRolePolicy
# - logs:CreateLogGroup, logs:PutLogEvents

# Contact your AWS administrator if you lack permissions
```

### Step 1.8: Get Agent ARN

Once deployed successfully, you need the Agent ARN for API Gateway setup:

```bash
# Get ARN from configuration file
cat .bedrock_agentcore.yaml | grep agent_arn

# Or from status command
agentcore status | grep "Agent ARN"

# Copy the ARN - you'll need it in Part 2
# Format: arn:aws:bedrock-agentcore:us-east-1:ACCOUNT_ID:runtime/langgraph_agent-XXXXX
```

**Save this ARN** - you'll use it in the Lambda proxy function.

---

## Part 2: Building API Gateway Infrastructure

### Why Do We Need API Gateway + Lambda?

**Problem**: AgentCore requires AWS SigV4 or OAuth authentication. Third-party servers (Azure, GCP, etc.) can't easily provide these.

**Solution**: API Gateway with API keys (simple) + Lambda proxy (adds SigV4 authentication)

**Architecture**:
```
Third-Party Server → API Gateway (API key auth) → Lambda Proxy (adds SigV4) → AgentCore Runtime → Agent
```

### Step 2.1: Set Your Configuration Variables

```bash
# Set your AWS account ID and region
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION="us-east-1"

# IMPORTANT: Extract the actual Agent ARN from .bedrock_agentcore.yaml
# DO NOT use a placeholder - this must be the real ARN from your deployment!
export AGENT_ARN=$(grep "agent_arn:" .bedrock_agentcore.yaml | awk '{print $2}')

# Verify the ARN was extracted correctly
if [[ -z "$AGENT_ARN" || "$AGENT_ARN" == *"XXXXX"* ]]; then
    echo "❌ ERROR: Could not extract Agent ARN from .bedrock_agentcore.yaml"
    echo "   Make sure you completed Step 1.6 (agentcore launch) successfully"
    echo "   Run: agentcore status"
    exit 1
fi

# Verify all variables
echo "Account ID: $AWS_ACCOUNT_ID"
echo "Region: $AWS_REGION"
echo "Agent ARN: $AGENT_ARN"

# Double-check the ARN format is valid
if [[ ! "$AGENT_ARN" =~ ^arn:aws:bedrock-agentcore: ]]; then
    echo "❌ WARNING: Agent ARN doesn't look valid. Expected format:"
    echo "   arn:aws:bedrock-agentcore:us-east-1:ACCOUNT_ID:runtime/AGENT_NAME"
    echo "   Got: $AGENT_ARN"
fi
```

> ⚠️ **CRITICAL**: The `AGENT_ARN` must be the actual ARN from your deployed agent, not a placeholder. If you see `langgraph_agent-XXXXX` in your ARN, something went wrong - go back to Step 1.8 and verify your deployment.

### Step 2.2: Create IAM Policies and Roles

**2.2.1: Create Lambda Trust Policy**

This allows Lambda service to assume the role.

```bash
cat > lambda-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
```

**2.2.2: Create Lambda Execution Policy**

This grants Lambda permissions to invoke AgentCore and write logs.

```bash
cat > lambda-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Sid": "InvokeAgentCore",
      "Effect": "Allow",
      "Action": "bedrock-agentcore:InvokeAgentRuntime",
      "Resource": "*"
    }
  ]
}
EOF
```

**Why `"Resource": "*"` for AgentCore?**
- The actual AgentCore endpoint ARN includes `/runtime-endpoint/DEFAULT` suffix
- Using wildcard (`*`) is simpler and works for all AgentCore agents in your account
- This is acceptable because Lambda only interacts with AgentCore, no other services

**2.2.3: Create IAM Role and Attach Policy**

```bash
# Create IAM role for Lambda
aws iam create-role \
  --role-name AgentCoreLambdaProxyRole \
  --assume-role-policy-document file://lambda-trust-policy.json \
  --region $AWS_REGION

# Create IAM policy
aws iam create-policy \
  --policy-name AgentCoreLambdaProxyPolicy \
  --policy-document file://lambda-policy.json \
  --region $AWS_REGION

# Attach policy to role
aws iam attach-role-policy \
  --role-name AgentCoreLambdaProxyRole \
  --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/AgentCoreLambdaProxyPolicy \
  --region $AWS_REGION

# Wait for IAM propagation (important!)
echo "Waiting 10 seconds for IAM propagation..."
sleep 10
```

**Verify role creation**:
```bash
aws iam get-role --role-name AgentCoreLambdaProxyRole --region $AWS_REGION
```

### Step 2.3: Create Lambda Proxy Function

**2.3.1: Create Lambda Function Code**

```bash
cat > lambda_proxy.py << 'EOF'
import json
import os
import urllib.request
import urllib.parse
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import boto3

# Configuration
AGENT_ARN = os.environ.get("AGENT_ARN", "REPLACE_WITH_YOUR_AGENT_ARN")
REGION = os.environ.get("AWS_REGION", "us-east-1")
QUALIFIER = "DEFAULT"

def lambda_handler(event, context):
    """
    Lambda proxy function that adds AWS SigV4 authentication
    to AgentCore invocation requests.

    Args:
        event: API Gateway event containing request data
        context: Lambda context object

    Returns:
        dict: API Gateway-formatted response
    """
    print(f"Received event: {json.dumps(event)}")

    try:
        # Parse request body from API Gateway
        body = json.loads(event.get('body', '{}'))
        prompt = body.get('prompt', '')
        actor_id = body.get('actor_id', 'api-user')
        thread_id = body.get('thread_id', 'api-session')

        # Validate prompt
        if not prompt:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Missing required field: prompt'})
            }

        # Prepare AgentCore payload
        agentcore_payload = {
            "prompt": prompt,
            "actor_id": actor_id,
            "thread_id": thread_id
        }
        print(f"AgentCore payload: {json.dumps(agentcore_payload)}")

        # Construct AgentCore endpoint URL
        # URL-encode the ARN for safe inclusion in URL
        encoded_arn = urllib.parse.quote(AGENT_ARN, safe='')
        url = f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier={QUALIFIER}"
        print(f"Invoking AgentCore URL: {url}")

        # Get AWS credentials from Lambda execution environment
        session = boto3.Session()
        credentials = session.get_credentials()

        # Create AWS request and sign with SigV4
        request = AWSRequest(
            method='POST',
            url=url,
            data=json.dumps(agentcore_payload),
            headers={
                'Content-Type': 'application/json'
            }
        )
        SigV4Auth(credentials, 'bedrock-agentcore', REGION).add_auth(request)

        # Make HTTP request to AgentCore
        req = urllib.request.Request(
            url,
            data=request.body.encode('utf-8') if isinstance(request.body, str) else request.body,
            headers=dict(request.headers)
        )

        with urllib.request.urlopen(req, timeout=60) as response:
            response_data = response.read().decode('utf-8')
            print(f"AgentCore response: {response_data}")

            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': response_data
            }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        print(f"HTTP Error {e.code}: {error_body}")
        return {
            'statusCode': e.code,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': f'AgentCore error: {e.code}',
                'details': error_body
            })
        }

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'error': 'Internal server error',
                'details': str(e)
            })
        }
EOF
```

**2.3.2: Update Lambda Code with Your Agent ARN**

```bash
# Replace placeholder with your actual Agent ARN
sed -i.bak "s|REPLACE_WITH_YOUR_AGENT_ARN|$AGENT_ARN|g" lambda_proxy.py

# Verify replacement
grep "AGENT_ARN" lambda_proxy.py
```

**2.3.3: Package Lambda Function**

```bash
# Create deployment package
zip lambda_function.zip lambda_proxy.py

# Verify zip contents
unzip -l lambda_function.zip
```

**2.3.4: Deploy Lambda Function**

```bash
# Create Lambda function
aws lambda create-function \
  --function-name AgentCoreProxy \
  --runtime python3.12 \
  --role "arn:aws:iam::${AWS_ACCOUNT_ID}:role/AgentCoreLambdaProxyRole" \
  --handler lambda_proxy.lambda_handler \
  --zip-file fileb://lambda_function.zip \
  --timeout 60 \
  --memory-size 256 \
  --environment "Variables={AGENT_ARN=${AGENT_ARN}}" \
  --region $AWS_REGION

# Wait for function to be active
echo "Waiting for Lambda function to be active..."
aws lambda wait function-active-v2 --function-name AgentCoreProxy --region $AWS_REGION
```

**Verify Lambda creation**:
```bash
aws lambda get-function --function-name AgentCoreProxy --region $AWS_REGION
```

### Step 2.4: Create API Gateway

**2.4.1: Create REST API**

```bash
# Create REST API
API_ID=$(aws apigateway create-rest-api \
  --name "AgentCore-FAQ-API" \
  --description "API Gateway for AgentCore FAQ Agent with API key authentication" \
  --region $AWS_REGION \
  --query 'id' \
  --output text)

echo "Created API Gateway with ID: $API_ID"

# Save API ID for later use
export API_ID=$API_ID
```

**2.4.2: Get Root Resource ID**

```bash
# Get root resource ID
ROOT_RESOURCE_ID=$(aws apigateway get-resources \
  --rest-api-id $API_ID \
  --region $AWS_REGION \
  --query 'items[0].id' \
  --output text)

echo "Root Resource ID: $ROOT_RESOURCE_ID"
```

**2.4.3: Create /invoke Resource**

```bash
# Create /invoke resource (ignore error if it already exists)
aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $ROOT_RESOURCE_ID \
  --path-part invoke \
  --region $AWS_REGION 2>/dev/null || echo "Note: /invoke resource may already exist, continuing..."

# Get the resource ID (works whether just created or already existed)
INVOKE_RESOURCE_ID=$(aws apigateway get-resources \
  --rest-api-id $API_ID \
  --region $AWS_REGION \
  --query "items[?pathPart=='invoke'].id" \
  --output text)

echo "INVOKE_RESOURCE_ID: $INVOKE_RESOURCE_ID"

# Verify we got a valid ID
if [ -z "$INVOKE_RESOURCE_ID" ]; then
    echo "❌ ERROR: Failed to get INVOKE_RESOURCE_ID"
    exit 1
fi
```



**2.4.4: Create POST Method with API Key Requirement**

```bash
# Create POST method on /invoke
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $INVOKE_RESOURCE_ID \
  --http-method POST \
  --authorization-type NONE \
  --api-key-required \
  --region $AWS_REGION

echo "Created POST method with API key requirement"
```

**2.4.5: Integrate with Lambda (AWS_PROXY)**

```bash
# Get Lambda ARN
LAMBDA_ARN="arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:AgentCoreProxy"

# Create integration
aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $INVOKE_RESOURCE_ID \
  --http-method POST \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:${AWS_REGION}:lambda:path/2015-03-31/functions/${LAMBDA_ARN}/invocations" \
  --region $AWS_REGION

echo "Created Lambda integration"
```

**2.4.6: Grant API Gateway Permission to Invoke Lambda**

```bash
# Add permission for API Gateway to invoke Lambda
aws lambda add-permission \
  --function-name AgentCoreProxy \
  --statement-id apigateway-invoke-permission \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:${AWS_REGION}:${AWS_ACCOUNT_ID}:${API_ID}/*/POST/invoke" \
  --region $AWS_REGION

echo "Granted API Gateway permission to invoke Lambda"
```

**2.4.7: Enable CORS (Required for Browser Access)**

> ⚠️ **When to use**: If you plan to access the API from a web browser (e.g., using `agent-ui.html`), you MUST enable CORS. Skip this step if you only need server-to-server access (curl, Python, etc.).

CORS (Cross-Origin Resource Sharing) allows browsers to make requests to your API from web pages.

```bash
# Create OPTIONS method for CORS preflight requests
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $INVOKE_RESOURCE_ID \
  --http-method OPTIONS \
  --authorization-type NONE \
  --region $AWS_REGION

echo "Created OPTIONS method"

# Add mock integration for OPTIONS (returns empty response with headers)
aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $INVOKE_RESOURCE_ID \
  --http-method OPTIONS \
  --type MOCK \
  --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
  --region $AWS_REGION

echo "Created OPTIONS mock integration"

# Add OPTIONS method response with CORS headers
aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $INVOKE_RESOURCE_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Origin":true}' \
  --region $AWS_REGION

echo "Created OPTIONS method response"

# Add OPTIONS integration response with actual CORS header values
aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $INVOKE_RESOURCE_ID \
  --http-method OPTIONS \
  --status-code 200 \
  --response-parameters '{"method.response.header.Access-Control-Allow-Headers":"'"'"'Content-Type,x-api-key'"'"'","method.response.header.Access-Control-Allow-Methods":"'"'"'POST,OPTIONS'"'"'","method.response.header.Access-Control-Allow-Origin":"'"'"'*'"'"'"}' \
  --region $AWS_REGION

echo "Created OPTIONS integration response with CORS headers"
```

**Add CORS headers to POST responses:**

For browser requests to work, the POST response also needs CORS headers. Since we're using Lambda proxy integration (AWS_PROXY), the Lambda function must return these headers.

Update the Lambda function to include CORS headers in responses. First, update `lambda_proxy.py`:

```bash
cat > lambda_proxy.py << 'EOF'
import json
import os
import urllib.request
import urllib.parse
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import boto3

# Configuration
AGENT_ARN = os.environ.get("AGENT_ARN", "REPLACE_WITH_YOUR_AGENT_ARN")
REGION = os.environ.get("AWS_REGION", "us-east-1")
QUALIFIER = "DEFAULT"

# CORS headers for browser access
CORS_HEADERS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,x-api-key',
    'Access-Control-Allow-Methods': 'POST,OPTIONS'
}

def lambda_handler(event, context):
    """
    Lambda proxy function that adds AWS SigV4 authentication
    to AgentCore invocation requests.
    """
    print(f"Received event: {json.dumps(event)}")

    try:
        # Parse request body from API Gateway
        body = json.loads(event.get('body', '{}'))
        prompt = body.get('prompt', '')
        actor_id = body.get('actor_id', 'api-user')
        thread_id = body.get('thread_id', 'api-session')

        # Validate prompt
        if not prompt:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({'error': 'Missing required field: prompt'})
            }

        # Prepare AgentCore payload
        agentcore_payload = {
            "prompt": prompt,
            "actor_id": actor_id,
            "thread_id": thread_id
        }
        print(f"AgentCore payload: {json.dumps(agentcore_payload)}")

        # Construct AgentCore endpoint URL
        encoded_arn = urllib.parse.quote(AGENT_ARN, safe='')
        url = f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier={QUALIFIER}"
        print(f"Invoking AgentCore URL: {url}")

        # Get AWS credentials from Lambda execution environment
        session = boto3.Session()
        credentials = session.get_credentials()

        # Create AWS request and sign with SigV4
        request = AWSRequest(
            method='POST',
            url=url,
            data=json.dumps(agentcore_payload),
            headers={
                'Content-Type': 'application/json'
            }
        )
        SigV4Auth(credentials, 'bedrock-agentcore', REGION).add_auth(request)

        # Make HTTP request to AgentCore
        req = urllib.request.Request(
            url,
            data=request.body.encode('utf-8') if isinstance(request.body, str) else request.body,
            headers=dict(request.headers)
        )

        with urllib.request.urlopen(req, timeout=60) as response:
            response_data = response.read().decode('utf-8')
            print(f"AgentCore response: {response_data}")

            return {
                'statusCode': 200,
                'headers': CORS_HEADERS,
                'body': response_data
            }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        print(f"HTTP Error {e.code}: {error_body}")
        return {
            'statusCode': e.code,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'error': f'AgentCore error: {e.code}',
                'details': error_body
            })
        }

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'error': 'Internal server error',
                'details': str(e)
            })
        }
EOF

# Update with your Agent ARN
sed -i.bak "s|REPLACE_WITH_YOUR_AGENT_ARN|$AGENT_ARN|g" lambda_proxy.py

# Repackage and update Lambda
zip lambda_function.zip lambda_proxy.py

aws lambda update-function-code \
  --function-name AgentCoreProxy \
  --zip-file fileb://lambda_function.zip \
  --region $AWS_REGION

# Wait for update
aws lambda wait function-updated-v2 --function-name AgentCoreProxy --region $AWS_REGION

echo "✅ Lambda updated with CORS headers"
```

### Step 2.5: Deploy API and Create API Key

**2.5.1: Deploy to Production Stage**

```bash
# Create deployment
DEPLOYMENT_ID=$(aws apigateway create-deployment \
  --rest-api-id $API_ID \
  --stage-name prod \
  --stage-description "Production stage" \
  --description "Initial deployment" \
  --region $AWS_REGION \
  --query 'id' \
  --output text)

echo "Created deployment: $DEPLOYMENT_ID"

# ⚠️ CRITICAL: Verify the stage was created successfully
STAGE_COUNT=$(aws apigateway get-stages \
  --rest-api-id $API_ID \
  --region $AWS_REGION \
  --query 'length(item[?stageName==`prod`])' \
  --output text)

if [[ "$STAGE_COUNT" != "1" ]]; then
    echo "❌ ERROR: Stage 'prod' was not created!"
    echo "   Check if the Lambda integration is properly configured."
    echo "   Common causes:"
    echo "   - Step 2.4.5 (put-integration) failed or was skipped"
    echo "   - Lambda function doesn't exist"
    aws apigateway get-stages --rest-api-id $API_ID --region $AWS_REGION
    exit 1
fi

echo "✅ Stage 'prod' created successfully"



```

> ⚠️ **If deployment fails with "No integration defined for method"**: Go back to Step 2.4.5 and ensure the Lambda integration was created. The integration is required before deployment.

**2.5.2: Create API Key**

```bash
# Create API key
API_KEY_VALUE=$(aws apigateway create-api-key \
  --name "ThirdPartyServerKey" \
  --description "API key for third-party servers to access AgentCore FAQ API" \
  --enabled \
  --region $AWS_REGION \
  --query 'id' \
  --output text)

echo "Created API key ID: $API_KEY_VALUE"

# Get the actual API key value
API_KEY=$(aws apigateway get-api-key \
  --api-key $API_KEY_VALUE \
  --include-value \
  --region $AWS_REGION \
  --query 'value' \
  --output text)

echo "API Key Value: $API_KEY"
echo ""
echo "⚠️ IMPORTANT: Save this API key securely! You'll need it for third-party integration."
```

**2.5.3: Create Usage Plan**

```bash
# Create usage plan with rate limits
USAGE_PLAN_ID=$(aws apigateway create-usage-plan \
  --name "ThirdPartyUsagePlan" \
  --description "Usage plan for third-party API access with rate limiting" \
  --throttle burstLimit=100,rateLimit=50 \
  --quota limit=10000,period=DAY \
  --region $AWS_REGION \
  --query 'id' \
  --output text)

echo "Created usage plan: $USAGE_PLAN_ID"
```

**Rate Limit Explanation**:
- `rateLimit=50`: 50 requests per second steady-state
- `burstLimit=100`: Up to 100 requests in a burst
- `quota limit=10000,period=DAY`: 10,000 requests per day maximum

**2.5.4: Associate API Key with Usage Plan**

```bash
# Link API key to usage plan
aws apigateway create-usage-plan-key \
  --usage-plan-id $USAGE_PLAN_ID \
  --key-id $API_KEY_VALUE \
  --key-type API_KEY \
  --region $AWS_REGION

# Associate usage plan with API stage
aws apigateway update-usage-plan \
  --usage-plan-id $USAGE_PLAN_ID \
  --patch-operations op=add,path=/apiStages,value="${API_ID}:prod" \
  --region $AWS_REGION

echo "Associated API key with usage plan and API stage"

# ⚠️ CRITICAL: Verify the associations are correct
echo ""
echo "Verifying configuration..."

# Check that API key is linked to usage plan
KEY_COUNT=$(aws apigateway get-usage-plan-keys \
  --usage-plan-id $USAGE_PLAN_ID \
  --region $AWS_REGION \
  --query 'length(items)' \
  --output text)

if [[ "$KEY_COUNT" == "0" ]]; then
    echo "❌ ERROR: API key not associated with usage plan!"
    exit 1
fi
echo "✅ API key linked to usage plan"

# Check that usage plan is linked to API stage
STAGE_LINKED=$(aws apigateway get-usage-plan \
  --usage-plan-id $USAGE_PLAN_ID \
  --region $AWS_REGION \
  --query "apiStages[?apiId=='${API_ID}' && stage=='prod'] | length(@)" \
  --output text)

if [[ "$STAGE_LINKED" == "0" ]]; then
    echo "❌ ERROR: Usage plan not linked to API stage!"
    echo "   This will cause 403 Forbidden errors even with valid API key"
    exit 1
fi
echo "✅ Usage plan linked to API stage (${API_ID}:prod)"
echo ""
echo "🎉 All verifications passed!"
```

> ⚠️ **Common Issue**: If you get "API Stage not found" error when running `update-usage-plan`, it means the deployment in Step 2.5.1 failed. Go back and verify the stage was created.

### Step 2.6: Save Configuration

```bash
# Create configuration file for future reference
cat > api-gateway-config.env << EOF
# API Gateway Configuration
export API_ID="$API_ID"
export API_ENDPOINT="https://$API_ID.execute-api.$AWS_REGION.amazonaws.com/prod/invoke"
export API_KEY="$API_KEY"
export API_KEY_ID="$API_KEY_VALUE"
export USAGE_PLAN_ID="$USAGE_PLAN_ID"

# Lambda Configuration
export LAMBDA_FUNCTION="AgentCoreProxy"
export LAMBDA_ARN="$LAMBDA_ARN"

# AgentCore Configuration
export AGENT_ARN="$AGENT_ARN"
export AWS_REGION="$AWS_REGION"
export AWS_ACCOUNT_ID="$AWS_ACCOUNT_ID"
EOF

echo ""
echo "✅ Configuration saved to api-gateway-config.env"
echo ""
echo "📋 Summary:"
echo "  - API Endpoint: https://$API_ID.execute-api.$AWS_REGION.amazonaws.com/prod/invoke"
echo "  - API Key: $API_KEY"
echo "  - Rate Limit: 50 req/s (burst: 100)"
echo "  - Daily Quota: 10,000 requests"
```

---

## Part 3: Testing and Validation

### Step 3.1: Test with curl

**Test 1: Valid API Key**

```bash
# Source configuration
source api-gateway-config.env

# Test with valid API key
curl -X POST "$API_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "prompt": "How do I activate roaming?",
    "actor_id": "test-user-001",
    "thread_id": "test-session-001"
  }'

# Expected response:
# {
#   "result": "To activate roaming, you need to...",
#   "actor_id": "test-user-001",
#   "thread_id": "test-session-001"
# }
```

**Test 2: Invalid API Key (Should Fail)**

```bash
curl -X POST "$API_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "x-api-key: invalid-key-12345" \
  -d '{"prompt": "Test query"}'

# Expected response:
# {"message":"Forbidden"}
# Status: 403
```

**Test 3: Missing API Key (Should Fail)**

```bash
curl -X POST "$API_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Test query"}'

# Expected response:
# {"message":"Forbidden"}
# Status: 403
```

### Step 3.2: Test with Python

Create a test script:

```bash
cat > test_api.py << 'EOF'
import requests
import json

# Load configuration
import os
with open('api-gateway-config.env', 'r') as f:
    for line in f:
        if line.startswith('export '):
            key, value = line.replace('export ', '').strip().split('=', 1)
            os.environ[key] = value.strip('"')

API_ENDPOINT = os.environ['API_ENDPOINT']
API_KEY = os.environ['API_KEY']

def test_agent(prompt, actor_id="test-user", thread_id="test-session"):
    """Test the AgentCore API"""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }

    payload = {
        "prompt": prompt,
        "actor_id": actor_id,
        "thread_id": thread_id
    }

    print(f"Testing with prompt: {prompt}")
    print(f"Endpoint: {API_ENDPOINT}")

    response = requests.post(API_ENDPOINT, headers=headers, json=payload, timeout=30)

    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print("-" * 80)

    return response.json()

# Test cases
if __name__ == "__main__":
    test_agent("How do I activate roaming?")
    test_agent("What are the available data plans?")
    test_agent("How do I check my balance?")
EOF

# Run tests
python test_api.py
```

### Step 3.3: Check CloudWatch Logs

**Lambda Logs**:
```bash
# Get recent Lambda logs
aws logs tail /aws/lambda/AgentCoreProxy --follow --region $AWS_REGION

# Or view specific log stream
aws logs describe-log-streams \
  --log-group-name /aws/lambda/AgentCoreProxy \
  --order-by LastEventTime \
  --descending \
  --max-items 1 \
  --region $AWS_REGION
```

**API Gateway Logs** (if enabled):
```bash
# Enable API Gateway logging (optional)
aws apigateway update-stage \
  --rest-api-id $API_ID \
  --stage-name prod \
  --patch-operations op=replace,path=/accessLogSettings/destinationArn,value=arn:aws:logs:$AWS_REGION:$AWS_ACCOUNT_ID:log-group:/aws/apigateway/$API_ID \
  --region $AWS_REGION
```

### Step 3.4: Verify Rate Limiting

Test rate limiting by sending multiple requests:

```bash
# Send 10 rapid requests
for i in {1..10}; do
  curl -X POST "$API_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "{\"prompt\": \"Test $i\"}" &
done
wait

# Check if any requests were throttled (429 Too Many Requests)
```

---

## Part 4: Third-Party Integration

### Integration Guide for Third-Party Developers

Share this section with third-party teams who will integrate with your API.

### Endpoint Details

**Base URL**: `https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod`
**Endpoint**: `/invoke`
**Method**: `POST`
**Content-Type**: `application/json`
**Authentication**: API Key in `x-api-key` header

### Request Format

**Headers**:
```
Content-Type: application/json
x-api-key: YOUR_API_KEY_HERE
```

**Body**:
```json
{
  "prompt": "Your question here",
  "actor_id": "optional-user-identifier",
  "thread_id": "optional-session-identifier"
}
```

**Required Fields**:
- `prompt` (string): The user's question or query

**Optional Fields**:
- `actor_id` (string): Identifier for the user making the request (for tracking/analytics)
- `thread_id` (string): Session or conversation identifier (for multi-turn conversations)

### Response Format

**Success Response** (200 OK):
```json
{
  "result": "Agent's response text",
  "actor_id": "user-identifier",
  "thread_id": "session-identifier"
}
```

**Error Responses**:

**403 Forbidden** (Invalid/Missing API Key):
```json
{
  "message": "Forbidden"
}
```

**400 Bad Request** (Missing prompt):
```json
{
  "error": "Missing required field: prompt"
}
```

**429 Too Many Requests** (Rate limit exceeded):
```json
{
  "message": "Too Many Requests"
}
```

**500 Internal Server Error**:
```json
{
  "error": "Internal server error",
  "details": "Error description"
}
```

### Rate Limits

- **Steady-state**: 50 requests per second
- **Burst**: Up to 100 requests in a burst
- **Daily quota**: 10,000 requests per day

### Code Examples

**Python** (using `requests`):
```python
import requests
import json

API_ENDPOINT = "https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod/invoke"
API_KEY = "your-api-key-here"

def call_agent(prompt, user_id=None, session_id=None):
    """Call the AgentCore FAQ API"""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }

    payload = {
        "prompt": prompt
    }

    if user_id:
        payload["actor_id"] = user_id
    if session_id:
        payload["thread_id"] = session_id

    try:
        response = requests.post(
            API_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.status_code}")
        print(f"Response: {e.response.text}")
        raise
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        raise

# Example usage
result = call_agent("How do I activate roaming?", user_id="user-123", session_id="session-456")
print(result["result"])
```

**Node.js** (using `axios`):
```javascript
const axios = require('axios');

const API_ENDPOINT = 'https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod/invoke';
const API_KEY = 'your-api-key-here';

async function callAgent(prompt, userId = null, sessionId = null) {
  const headers = {
    'Content-Type': 'application/json',
    'x-api-key': API_KEY
  };

  const payload = { prompt };
  if (userId) payload.actor_id = userId;
  if (sessionId) payload.thread_id = sessionId;

  try {
    const response = await axios.post(API_ENDPOINT, payload, { headers });
    return response.data;
  } catch (error) {
    if (error.response) {
      console.error(`HTTP Error: ${error.response.status}`);
      console.error(`Response: ${JSON.stringify(error.response.data)}`);
    } else {
      console.error(`Request failed: ${error.message}`);
    }
    throw error;
  }
}

// Example usage
callAgent('How do I activate roaming?', 'user-123', 'session-456')
  .then(result => console.log(result.result))
  .catch(error => console.error(error));
```

**C#** (using `HttpClient`):
```csharp
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

public class AgentCoreClient
{
    private readonly string apiEndpoint = "https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod/invoke";
    private readonly string apiKey = "your-api-key-here";
    private readonly HttpClient client = new HttpClient();

    public async Task<string> CallAgent(string prompt, string userId = null, string sessionId = null)
    {
        var payload = new
        {
            prompt = prompt,
            actor_id = userId,
            thread_id = sessionId
        };

        var request = new HttpRequestMessage(HttpMethod.Post, apiEndpoint)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json"
            )
        };
        request.Headers.Add("x-api-key", apiKey);

        try
        {
            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseBody = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<JsonElement>(responseBody);
            return result.GetProperty("result").GetString();
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Request failed: {e.Message}");
            throw;
        }
    }
}

// Example usage
var client = new AgentCoreClient();
var result = await client.CallAgent("How do I activate roaming?", "user-123", "session-456");
Console.WriteLine(result);
```

**curl** (for testing):
```bash
curl -X POST https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod/invoke \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key-here" \
  -d '{
    "prompt": "How do I activate roaming?",
    "actor_id": "user-123",
    "thread_id": "session-456"
  }'
```

### Best Practices

1. **Store API Key Securely**
   - Use environment variables or secret management services
   - Never commit API keys to version control
   - Rotate keys periodically

2. **Handle Rate Limits**
   - Implement exponential backoff for 429 errors
   - Cache responses when appropriate
   - Monitor your usage against quota

3. **Error Handling**
   - Always check HTTP status codes
   - Log failed requests for debugging
   - Provide user-friendly error messages

4. **Timeout Configuration**
   - Set reasonable timeouts (30-60 seconds)
   - Agent responses can take 5-15 seconds depending on complexity

5. **Session Management**
   - Use consistent `thread_id` for multi-turn conversations
   - Use unique `actor_id` per user for analytics

---

## Part 5: Troubleshooting

### Common Issues and Solutions

#### Issue 1: "Forbidden" (403) Response

**Symptom**: All requests return `{"message":"Forbidden"}`

**Possible Causes**:
1. Invalid or missing API key
2. API key not associated with usage plan
3. API key disabled
4. **API Gateway stage not deployed** (no `prod` stage exists)
5. **Usage plan not linked to API stage** (`apiStages: []` is empty)
6. **Lambda integration missing** (method has no integration defined)

**Diagnostic Commands**:
```bash
# 1. Check API key status and if it's enabled
aws apigateway get-api-key \
  --api-key $API_KEY_ID \
  --include-value \
  --region $AWS_REGION

# 2. Check if stage exists
aws apigateway get-stages \
  --rest-api-id $API_ID \
  --region $AWS_REGION

# 3. Check if usage plan is linked to API stage
aws apigateway get-usage-plan \
  --usage-plan-id $USAGE_PLAN_ID \
  --region $AWS_REGION
# Look for: "apiStages": [{"apiId": "...", "stage": "prod"}]

# 4. Check if API key is linked to usage plan
aws apigateway get-usage-plan-keys \
  --usage-plan-id $USAGE_PLAN_ID \
  --region $AWS_REGION

# 5. Check if Lambda integration exists
aws apigateway get-method \
  --rest-api-id $API_ID \
  --resource-id $INVOKE_RESOURCE_ID \
  --http-method POST \
  --region $AWS_REGION
# Look for: "methodIntegration": {...}
```

**Solutions**:
```bash
# Fix 1: Enable API key
aws apigateway update-api-key \
  --api-key $API_KEY_ID \
  --patch-operations op=replace,path=/enabled,value=true \
  --region $AWS_REGION

# Fix 2: Re-associate API key with usage plan
aws apigateway create-usage-plan-key \
  --usage-plan-id $USAGE_PLAN_ID \
  --key-id $API_KEY_ID \
  --key-type API_KEY \
  --region $AWS_REGION

# Fix 3: Link usage plan to API stage (if apiStages is empty)
aws apigateway update-usage-plan \
  --usage-plan-id $USAGE_PLAN_ID \
  --patch-operations op=add,path=/apiStages,value="${API_ID}:prod" \
  --region $AWS_REGION

# Fix 4: Redeploy API (if stage doesn't exist)
aws apigateway create-deployment \
  --rest-api-id $API_ID \
  --stage-name prod \
  --region $AWS_REGION
```

#### Issue 2: Lambda Timeout or 504 Gateway Timeout

**Symptom**: Requests timeout after 30-60 seconds

**Possible Causes**:
1. AgentCore agent is slow or not responding
2. Lambda timeout too short
3. Network issues

**Solutions**:
```bash
# Increase Lambda timeout to 90 seconds
aws lambda update-function-configuration \
  --function-name AgentCoreProxy \
  --timeout 90 \
  --region $AWS_REGION

# Check AgentCore agent status
agentcore status

# Check Lambda logs for errors
aws logs tail /aws/lambda/AgentCoreProxy --follow --region $AWS_REGION
```

#### Issue 3: "User is not authorized to perform bedrock-agentcore:InvokeAgentRuntime"

**Symptom**: Lambda logs show permission denied errors

**Possible Causes**:
1. IAM policy not attached to Lambda role
2. Policy resource ARN too specific

**Solutions**:
```bash
# Verify policy is attached
aws iam list-attached-role-policies \
  --role-name AgentCoreLambdaProxyRole \
  --region $AWS_REGION

# If not attached, attach it
aws iam attach-role-policy \
  --role-name AgentCoreLambdaProxyRole \
  --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/AgentCoreLambdaProxyPolicy \
  --region $AWS_REGION

# Update policy to use wildcard resource
aws iam create-policy-version \
  --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/AgentCoreLambdaProxyPolicy \
  --policy-document file://lambda-policy.json \
  --set-as-default \
  --region $AWS_REGION
```

#### Issue 4: "Too Many Requests" (429)

**Symptom**: Requests fail with 429 after burst

**Possible Causes**:
1. Rate limit exceeded
2. Burst limit exceeded

**Solutions**:
```bash
# Increase rate limits in usage plan
aws apigateway update-usage-plan \
  --usage-plan-id $USAGE_PLAN_ID \
  --patch-operations \
    op=replace,path=/throttle/rateLimit,value=100 \
    op=replace,path=/throttle/burstLimit,value=200 \
  --region $AWS_REGION

# Or implement exponential backoff in client code
```

#### Issue 5: Invalid Response Format

**Symptom**: Response is not JSON or has unexpected structure

**Possible Causes**:
1. Lambda error not caught
2. AgentCore returning error response
3. Integration response mapping issue

**Solutions**:
```bash
# Check Lambda logs for errors
aws logs tail /aws/lambda/AgentCoreProxy --follow --region $AWS_REGION

# Test Lambda directly
aws lambda invoke \
  --function-name AgentCoreProxy \
  --payload '{"body": "{\"prompt\": \"test\"}"}' \
  response.json \
  --region $AWS_REGION

cat response.json

# Check AgentCore agent status
agentcore status
agentcore invoke '{"prompt": "test"}'
```

### Debugging Checklist

When troubleshooting issues, check these in order:

1. **API Key Validation**
   ```bash
   # Test with known-good API key
   curl -X POST "$API_ENDPOINT" -H "x-api-key: $API_KEY" -H "Content-Type: application/json" -d '{"prompt": "test"}'
   ```

2. **Lambda Function Health**
   ```bash
   # Test Lambda directly
   aws lambda invoke --function-name AgentCoreProxy --payload '{"body": "{\"prompt\": \"test\"}"}' response.json --region $AWS_REGION
   ```

3. **AgentCore Agent Health**
   ```bash
   # Test AgentCore directly
   agentcore invoke '{"prompt": "test"}'
   agentcore status
   ```

4. **IAM Permissions**
   ```bash
   # Verify Lambda role has correct policies
   aws iam list-attached-role-policies --role-name AgentCoreLambdaProxyRole --region $AWS_REGION
   ```

5. **CloudWatch Logs**
   ```bash
   # Check logs for errors
   aws logs tail /aws/lambda/AgentCoreProxy --follow --region $AWS_REGION
   ```

---

## Part 6: Maintenance and Updates

### Updating the Agent

When you make changes to your agent code:

```bash
# 1. Update agent code (01_agentcore_runtime.py)
# ... make your changes ...

# 2. Reconfigure (if needed)
agentcore configure -e 01_agentcore_runtime.py

# 3. Redeploy
agentcore launch --env GROQ_API_KEY=$GROQ_API_KEY

# 4. Test
agentcore invoke '{"prompt": "test"}'

# 5. No changes needed to API Gateway or Lambda!
# The same Lambda proxy will work with the new agent deployment
```

### Updating Lambda Function

If you need to update the Lambda proxy:

```bash
# 1. Update lambda_proxy.py
# ... make your changes ...

# 2. Repackage
zip lambda_function.zip lambda_proxy.py

# 3. Update Lambda function
aws lambda update-function-code \
  --function-name AgentCoreProxy \
  --zip-file fileb://lambda_function.zip \
  --region $AWS_REGION

# 4. Wait for update
aws lambda wait function-updated-v2 --function-name AgentCoreProxy --region $AWS_REGION

# 5. Test
curl -X POST "$API_ENDPOINT" -H "x-api-key: $API_KEY" -H "Content-Type: application/json" -d '{"prompt": "test"}'
```

### Rotating API Keys

For security, rotate API keys periodically:

```bash
# 1. Create new API key
NEW_API_KEY_ID=$(aws apigateway create-api-key \
  --name "ThirdPartyServerKey-$(date +%Y%m%d)" \
  --description "Rotated API key" \
  --enabled \
  --region $AWS_REGION \
  --query 'id' \
  --output text)

# 2. Get key value
NEW_API_KEY=$(aws apigateway get-api-key \
  --api-key $NEW_API_KEY_ID \
  --include-value \
  --region $AWS_REGION \
  --query 'value' \
  --output text)

# 3. Associate with usage plan
aws apigateway create-usage-plan-key \
  --usage-plan-id $USAGE_PLAN_ID \
  --key-id $NEW_API_KEY_ID \
  --key-type API_KEY \
  --region $AWS_REGION

# 4. Share new key with third-parties
echo "New API Key: $NEW_API_KEY"

# 5. After migration, disable old key
aws apigateway update-api-key \
  --api-key $API_KEY_ID \
  --patch-operations op=replace,path=/enabled,value=false \
  --region $AWS_REGION

# 6. After verification, delete old key
aws apigateway delete-api-key \
  --api-key $API_KEY_ID \
  --region $AWS_REGION
```

### Monitoring

**Set up CloudWatch Alarms**:

```bash
# Alarm for high error rate
aws cloudwatch put-metric-alarm \
  --alarm-name AgentCoreProxy-HighErrorRate \
  --alarm-description "Triggers when Lambda error rate exceeds 5%" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Average \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=FunctionName,Value=AgentCoreProxy \
  --region $AWS_REGION

# Alarm for rate limiting
aws cloudwatch put-metric-alarm \
  --alarm-name APIGateway-HighThrottle \
  --alarm-description "Triggers when API requests are throttled" \
  --metric-name 429 \
  --namespace AWS/ApiGateway \
  --statistic Sum \
  --period 60 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimensions Name=ApiName,Value=AgentCore-FAQ-API \
  --region $AWS_REGION
```

**Check Metrics**:
```bash
# API Gateway metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApiGateway \
  --metric-name Count \
  --dimensions Name=ApiName,Value=AgentCore-FAQ-API \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum \
  --region $AWS_REGION

# Lambda metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=AgentCoreProxy \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum \
  --region $AWS_REGION
```

### Cost Optimization

**Monitor Costs**:
```bash
# Check current month costs (requires Cost Explorer API access)
aws ce get-cost-and-usage \
  --time-period Start=$(date -u +%Y-%m-01),End=$(date -u +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=SERVICE
```

**Expected Monthly Costs** (for 1M requests):
- API Gateway: ~$3.50
- Lambda: ~$4.17
- AgentCore: Variable based on compute time
- Total: ~$8-15/month (excluding AgentCore compute)

**Cost Saving Tips**:
1. Use Lambda reserved concurrency only if needed
2. Enable API Gateway caching for repeated queries
3. Monitor and adjust rate limits based on actual usage
4. Review CloudWatch log retention settings

### Cleanup

If you need to delete all resources, see `CLEANUP_GUIDE.md` for detailed instructions.

Quick cleanup:
```bash
# Delete API Gateway
aws apigateway delete-rest-api --rest-api-id $API_ID --region $AWS_REGION

# Delete Lambda
aws lambda delete-function --function-name AgentCoreProxy --region $AWS_REGION

# Delete IAM policy and role
aws iam detach-role-policy --role-name AgentCoreLambdaProxyRole --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/AgentCoreLambdaProxyPolicy --region $AWS_REGION
aws iam delete-policy --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/AgentCoreLambdaProxyPolicy --region $AWS_REGION
aws iam delete-role --role-name AgentCoreLambdaProxyRole --region $AWS_REGION

# Delete AgentCore agent
agentcore delete
```

---

## Summary

You've successfully deployed a production-ready AI agent with the following components:

**What You Built**:
1. **LangGraph FAQ Agent** with RAG capabilities (FAISS vector store)
2. **AgentCore Runtime** - Fully managed AWS deployment
3. **Lambda Proxy** - Adds AWS SigV4 authentication
4. **API Gateway** - Provides simple API key authentication
5. **Rate Limiting** - 50 req/s, 100 burst, 10K/day quota

**Architecture**:
```
Third-Party Server
  ↓ (HTTP POST with API key)
API Gateway
  ↓ (validates API key)
Lambda Proxy
  ↓ (adds SigV4 authentication)
AgentCore Runtime
  ↓
LangGraph Agent
  ↓
Tools (FAQ Search) + LLM
  ↓
Response
```

**Key Endpoints**:
- **API Endpoint**: `https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod/invoke`
- **Method**: POST
- **Auth**: `x-api-key` header
- **Payload**: `{"prompt": "question", "actor_id": "user", "thread_id": "session"}`

**Next Steps**:
1. Share API key and integration guide with third-party teams
2. Monitor CloudWatch metrics and logs
3. Set up alarms for errors and throttling
4. Plan for API key rotation
5. Consider implementing caching for frequently asked questions

**Reference Documents**:
- `API_GATEWAY_SETUP_GUIDE.md` - Detailed API Gateway setup
- `IMPLEMENTATION_COMPLETE.md` - Implementation summary
- `CLEANUP_GUIDE.md` - Resource deletion instructions
- `CLAUDE.md` - Project overview and commands
- `api-gateway-config.env` - Configuration values

**Support**:
- Check CloudWatch logs for errors: `/aws/lambda/AgentCoreProxy`
- Test AgentCore directly: `agentcore invoke '{"prompt": "test"}'`
- Review troubleshooting section for common issues

---

**🎉 Congratulations!** You've built a production-ready AI agent API that can handle third-party integrations securely and at scale.
