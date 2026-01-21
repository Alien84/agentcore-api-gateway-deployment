#!/bin/bash

#############################################################################
# AWS AgentCore API Gateway Cleanup Script
#############################################################################
#
# This script deletes all AWS resources created by the deployment guide:
# - API Gateway REST API (includes API keys, usage plans, deployments)
# - Lambda function (AgentCoreProxy)
# - IAM policies and roles
# - CloudWatch log groups (optional)
# - AgentCore agent (optional)
# - ECR repositories (optional)
# - Local files (optional): .bedrock_agentcore.yaml, api-gateway-config.env, Lambda files
#
# Usage: ./cleanup.sh
#
# Note: This script will prompt for confirmation before deleting resources.
#############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - Load from api-gateway-config.env if it exists
if [ -f "api-gateway-config.env" ]; then
    echo -e "${BLUE}Loading configuration from api-gateway-config.env...${NC}"
    source api-gateway-config.env
else
    echo -e "${YELLOW}Warning: api-gateway-config.env not found. You'll need to enter values manually.${NC}"
fi

# Prompt for configuration if not set
if [ -z "$AWS_REGION" ]; then
    read -p "Enter AWS region (default: us-east-1): " AWS_REGION
    AWS_REGION=${AWS_REGION:-us-east-1}
fi

if [ -z "$AWS_ACCOUNT_ID" ]; then
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
    if [ -z "$AWS_ACCOUNT_ID" ]; then
        read -p "Enter AWS Account ID: " AWS_ACCOUNT_ID
    fi
fi

if [ -z "$API_ID" ]; then
    read -p "Enter API Gateway ID (or press Enter to skip): " API_ID
fi

if [ -z "$LAMBDA_FUNCTION" ]; then
    LAMBDA_FUNCTION="AgentCoreProxy"
fi

# Display what will be deleted
echo ""
echo -e "${RED}⚠️  WARNING: This will permanently delete the following AWS resources:${NC}"
echo ""
echo "1. API Gateway REST API"
if [ -n "$API_ID" ]; then
    echo "   - API ID: $API_ID"
fi
echo "   - All API keys, usage plans, and deployments"
echo ""
echo "2. Lambda Function"
echo "   - Function Name: $LAMBDA_FUNCTION"
echo ""
echo "3. IAM Policies"
echo "   - AgentCoreLambdaProxyPolicy"
echo ""
echo "4. IAM Roles"
echo "   - AgentCoreLambdaProxyRole"
echo ""
echo "5. AgentCore Agent (optional)"
echo "   - Deployed agent runtime"
echo "   - AgentCore CloudWatch logs"
echo ""
echo "6. ECR Repositories (optional)"
echo "   - All bedrock-agentcore repositories"
echo "   - All Docker images in those repositories"
echo ""
echo "7. CloudWatch Log Groups (optional)"
echo "   - /aws/lambda/$LAMBDA_FUNCTION"
echo "   - /aws/apigateway/* (if exists)"
echo ""
echo "8. Local Files (optional)"
echo "   - .bedrock_agentcore.yaml"
echo "   - api-gateway-config.env"
echo "   - lambda_proxy.py, lambda_function.zip"
echo "   - lambda-policy.json, lambda-trust-policy.json"
echo ""
echo -e "${YELLOW}⚠️  Third-party integrations will stop working immediately after deletion.${NC}"
echo -e "${YELLOW}⚠️  ECR images (potentially several GB) will be permanently deleted.${NC}"
echo ""

# Confirmation prompt
read -p "Are you sure you want to continue? Type 'yes' to confirm: " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo ""
    echo -e "${GREEN}Cleanup cancelled. No resources were deleted.${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}Starting cleanup...${NC}"
echo ""

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "   ${GREEN}✅ $2${NC}"
    else
        echo -e "   ${YELLOW}⚠️  $2${NC}"
    fi
}

#############################################################################
# Step 1: Delete API Gateway
#############################################################################

echo -e "${BLUE}Step 1: Deleting API Gateway REST API...${NC}"

if [ -n "$API_ID" ]; then
    aws apigateway delete-rest-api \
        --rest-api-id "$API_ID" \
        --region "$AWS_REGION" 2>/dev/null && \
        print_status 0 "API Gateway deleted (API ID: $API_ID)" || \
        print_status 1 "API Gateway not found or already deleted"
else
    echo -e "   ${YELLOW}⏭️  Skipping (no API ID provided)${NC}"
fi

echo ""

#############################################################################
# Step 2: Delete Lambda Function
#############################################################################

echo -e "${BLUE}Step 2: Deleting Lambda function...${NC}"

aws lambda delete-function \
    --function-name "$LAMBDA_FUNCTION" \
    --region "$AWS_REGION" 2>/dev/null && \
    print_status 0 "Lambda function deleted ($LAMBDA_FUNCTION)" || \
    print_status 1 "Lambda function not found or already deleted"

echo ""

#############################################################################
# Step 3: Detach and Delete IAM Policy
#############################################################################

echo -e "${BLUE}Step 3: Detaching and deleting IAM policies...${NC}"

# Detach policy from Lambda role
aws iam detach-role-policy \
    --role-name AgentCoreLambdaProxyRole \
    --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/AgentCoreLambdaProxyPolicy" 2>/dev/null && \
    print_status 0 "Policy detached from Lambda role" || \
    print_status 1 "Policy already detached or not found"

# Delete policy
aws iam delete-policy \
    --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/AgentCoreLambdaProxyPolicy" 2>/dev/null && \
    print_status 0 "Lambda IAM policy deleted" || \
    print_status 1 "Lambda IAM policy not found or already deleted"

echo ""

#############################################################################
# Step 4: Delete IAM Roles
#############################################################################

echo -e "${BLUE}Step 4: Deleting IAM roles...${NC}"

# Delete Lambda role
aws iam delete-role \
    --role-name AgentCoreLambdaProxyRole 2>/dev/null && \
    print_status 0 "Lambda IAM role deleted" || \
    print_status 1 "Lambda IAM role not found or already deleted"

# Check for API Gateway role (may not exist)
aws iam delete-role \
    --role-name AgentCoreAPIGatewayRole 2>/dev/null && \
    print_status 0 "API Gateway IAM role deleted" || \
    print_status 1 "API Gateway IAM role not found (this is normal)"

echo ""

#############################################################################
# Step 5: Delete AgentCore Agent (Optional)
#############################################################################

echo -e "${BLUE}Step 5: AgentCore agent...${NC}"
echo -e "   ${YELLOW}Note: This will delete your deployed AgentCore agent and related resources.${NC}"
read -p "   Delete AgentCore agent? (y/n): " DELETE_AGENT

if [ "$DELETE_AGENT" = "y" ] || [ "$DELETE_AGENT" = "Y" ]; then
    if command -v agentcore &> /dev/null; then
        # Get agent ID from config file if it exists
        AGENT_ID=""
        if [ -f ".bedrock_agentcore.yaml" ]; then
            AGENT_ID=$(grep "agent_id:" .bedrock_agentcore.yaml | awk '{print $2}' | tr -d '"')
            echo -e "   ${BLUE}Found agent ID: $AGENT_ID${NC}"
        fi

        # Destroy AgentCore agent
        agentcore destroy 2>/dev/null && \
            print_status 0 "AgentCore agent destroyed" || \
            print_status 1 "AgentCore agent not found or already destroyed"

        # Wait a bit for deletion to propagate
        sleep 2

        # Delete AgentCore CloudWatch logs if agent ID is known
        if [ -n "$AGENT_ID" ]; then
            echo -e "   ${BLUE}Checking for AgentCore log groups...${NC}"

            # Find and delete all log groups matching the agent pattern
            LOG_GROUPS=$(aws logs describe-log-groups \
                --log-group-name-prefix "/aws/bedrock-agentcore/runtimes/$AGENT_ID" \
                --region "$AWS_REGION" \
                --query 'logGroups[*].logGroupName' \
                --output text 2>/dev/null || echo "")

            if [ -n "$LOG_GROUPS" ]; then
                for LOG_GROUP in $LOG_GROUPS; do
                    aws logs delete-log-group \
                        --log-group-name "$LOG_GROUP" \
                        --region "$AWS_REGION" 2>/dev/null && \
                        print_status 0 "Deleted log group: $LOG_GROUP" || \
                        print_status 1 "Could not delete log group: $LOG_GROUP"
                done
            else
                print_status 1 "No AgentCore log groups found"
            fi
        fi
    else
        echo -e "   ${YELLOW}⚠️  agentcore CLI not found. You'll need to delete the agent manually.${NC}"
    fi
else
    echo -e "   ${YELLOW}⏭️  Skipping AgentCore agent deletion (agent will continue running)${NC}"
fi

echo ""

#############################################################################
# Step 6: Delete ECR Repositories
#############################################################################

echo -e "${BLUE}Step 6: ECR repositories...${NC}"
read -p "   Delete ECR repositories created by AgentCore? (y/n): " DELETE_ECR

if [ "$DELETE_ECR" = "y" ] || [ "$DELETE_ECR" = "Y" ]; then
    echo -e "   ${BLUE}Searching for AgentCore ECR repositories...${NC}"

    # Find ECR repositories with bedrock-agentcore prefix
    ECR_REPOS=$(aws ecr describe-repositories \
        --region "$AWS_REGION" \
        --query 'repositories[?starts_with(repositoryName, `bedrock-agentcore`)].repositoryName' \
        --output text 2>/dev/null || echo "")

    if [ -n "$ECR_REPOS" ]; then
        for REPO in $ECR_REPOS; do
            echo -e "   ${BLUE}Deleting ECR repository: $REPO${NC}"

            # Delete repository with --force to delete all images
            aws ecr delete-repository \
                --repository-name "$REPO" \
                --force \
                --region "$AWS_REGION" 2>/dev/null && \
                print_status 0 "ECR repository deleted: $REPO" || \
                print_status 1 "Could not delete ECR repository: $REPO"
        done
    else
        print_status 1 "No AgentCore ECR repositories found"
    fi
else
    echo -e "   ${YELLOW}⏭️  Skipping ECR deletion (repositories will remain and incur storage costs)${NC}"
fi

echo ""

#############################################################################
# Step 7: Delete CloudWatch Log Groups (Optional)
#############################################################################

echo -e "${BLUE}Step 7: Lambda and API Gateway CloudWatch logs...${NC}"
read -p "   Delete Lambda/API Gateway CloudWatch logs? (y/n): " DELETE_LOGS

if [ "$DELETE_LOGS" = "y" ] || [ "$DELETE_LOGS" = "Y" ]; then
    aws logs delete-log-group \
        --log-group-name "/aws/lambda/$LAMBDA_FUNCTION" \
        --region "$AWS_REGION" 2>/dev/null && \
        print_status 0 "Lambda logs deleted" || \
        print_status 1 "Lambda logs not found or already deleted"

    # Try to delete API Gateway logs if they exist
    if [ -n "$API_ID" ]; then
        aws logs delete-log-group \
            --log-group-name "/aws/apigateway/$API_ID" \
            --region "$AWS_REGION" 2>/dev/null && \
            print_status 0 "API Gateway logs deleted" || \
            print_status 1 "API Gateway logs not found (this is normal)"
    fi
else
    echo -e "   ${YELLOW}⏭️  Skipping log deletion (logs will remain and continue to incur minimal storage costs)${NC}"
fi

echo ""

#############################################################################
# Step 8: Delete Local Files and Folders (Optional)
#############################################################################

echo -e "${BLUE}Step 8: Local configuration and Lambda files...${NC}"
echo -e "   ${YELLOW}Note: This will delete local config files, Lambda code, and AgentCore config.${NC}"
read -p "   Delete local files (.bedrock_agentcore.yaml, api-gateway-config.env, Lambda files)? (y/n): " DELETE_LOCAL

if [ "$DELETE_LOCAL" = "y" ] || [ "$DELETE_LOCAL" = "Y" ]; then
    # Delete .bedrock_agentcore.yaml
    if [ -f ".bedrock_agentcore.yaml" ]; then
        rm -f ".bedrock_agentcore.yaml" && \
            print_status 0 "Deleted .bedrock_agentcore.yaml" || \
            print_status 1 "Could not delete .bedrock_agentcore.yaml"
    else
        print_status 1 ".bedrock_agentcore.yaml not found"
    fi

    # Delete api-gateway-config.env
    if [ -f "api-gateway-config.env" ]; then
        rm -f "api-gateway-config.env" && \
            print_status 0 "Deleted api-gateway-config.env" || \
            print_status 1 "Could not delete api-gateway-config.env"
    else
        print_status 1 "api-gateway-config.env not found"
    fi

    # Delete Lambda files
    LAMBDA_FILES=("lambda_proxy.py" "lambda_function.zip" "lambda-policy.json" "lambda-trust-policy.json")
    for FILE in "${LAMBDA_FILES[@]}"; do
        if [ -f "$FILE" ]; then
            rm -f "$FILE" && \
                print_status 0 "Deleted $FILE" || \
                print_status 1 "Could not delete $FILE"
        else
            print_status 1 "$FILE not found"
        fi
    done
else
    echo -e "   ${YELLOW}⏭️  Skipping local file deletion (files will remain on disk)${NC}"
fi

echo ""

#############################################################################
# Step 9: Verify Cleanup
#############################################################################

echo -e "${BLUE}Step 9: Verifying cleanup...${NC}"
echo ""

# Check API Gateway
if [ -n "$API_ID" ]; then
    if aws apigateway get-rest-api --rest-api-id "$API_ID" --region "$AWS_REGION" &>/dev/null; then
        echo -e "   ${RED}❌ API Gateway still exists${NC}"
    else
        echo -e "   ${GREEN}✅ API Gateway deleted${NC}"
    fi
fi

# Check Lambda
if aws lambda get-function --function-name "$LAMBDA_FUNCTION" --region "$AWS_REGION" &>/dev/null; then
    echo -e "   ${RED}❌ Lambda function still exists${NC}"
else
    echo -e "   ${GREEN}✅ Lambda function deleted${NC}"
fi

# Check IAM policy
if aws iam get-policy --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/AgentCoreLambdaProxyPolicy" &>/dev/null; then
    echo -e "   ${RED}❌ IAM policy still exists${NC}"
else
    echo -e "   ${GREEN}✅ IAM policy deleted${NC}"
fi

# Check IAM role
if aws iam get-role --role-name AgentCoreLambdaProxyRole &>/dev/null; then
    echo -e "   ${RED}❌ IAM role still exists${NC}"
else
    echo -e "   ${GREEN}✅ IAM role deleted${NC}"
fi

# Check AgentCore agent (if deleted)
if [ "$DELETE_AGENT" = "y" ] || [ "$DELETE_AGENT" = "Y" ]; then
    if command -v agentcore &> /dev/null; then
        if agentcore status &>/dev/null; then
            echo -e "   ${RED}❌ AgentCore agent still exists${NC}"
        else
            echo -e "   ${GREEN}✅ AgentCore agent deleted${NC}"
        fi
    fi
fi

# Check ECR repositories (if deleted)
if [ "$DELETE_ECR" = "y" ] || [ "$DELETE_ECR" = "Y" ]; then
    ECR_CHECK=$(aws ecr describe-repositories --region "$AWS_REGION" --query 'repositories[?starts_with(repositoryName, `bedrock-agentcore`)].repositoryName' --output text 2>/dev/null || echo "")
    if [ -n "$ECR_CHECK" ]; then
        echo -e "   ${RED}❌ ECR repositories still exist${NC}"
    else
        echo -e "   ${GREEN}✅ ECR repositories deleted${NC}"
    fi
fi

# Check CloudWatch logs (if deleted)
if [ "$DELETE_LOGS" = "y" ] || [ "$DELETE_LOGS" = "Y" ]; then
    if aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/$LAMBDA_FUNCTION" --region "$AWS_REGION" --query 'logGroups' --output text 2>/dev/null | grep -q "/aws/lambda/$LAMBDA_FUNCTION"; then
        echo -e "   ${RED}❌ Lambda CloudWatch logs still exist${NC}"
    else
        echo -e "   ${GREEN}✅ Lambda CloudWatch logs deleted${NC}"
    fi
fi

# Check local files (if deleted)
if [ "$DELETE_LOCAL" = "y" ] || [ "$DELETE_LOCAL" = "Y" ]; then
    LOCAL_FILES_REMAINING=0
    for FILE in ".bedrock_agentcore.yaml" "api-gateway-config.env" "lambda_proxy.py" "lambda_function.zip" "lambda-policy.json" "lambda-trust-policy.json"; do
        if [ -f "$FILE" ]; then
            LOCAL_FILES_REMAINING=1
            break
        fi
    done
    if [ $LOCAL_FILES_REMAINING -eq 1 ]; then
        echo -e "   ${RED}❌ Some local files still exist${NC}"
    else
        echo -e "   ${GREEN}✅ Local files deleted${NC}"
    fi
fi

echo ""

#############################################################################
# Summary
#############################################################################

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Cleanup complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Summary of deleted resources:"
echo "  - API Gateway: $([ -n "$API_ID" ] && echo "deleted" || echo "skipped")"
echo "  - Lambda function: deleted"
echo "  - IAM policies and roles: deleted"
echo "  - AgentCore agent: $([ "$DELETE_AGENT" = "y" ] || [ "$DELETE_AGENT" = "Y" ] && echo "deleted" || echo "kept")"
echo "  - ECR repositories: $([ "$DELETE_ECR" = "y" ] || [ "$DELETE_ECR" = "Y" ] && echo "deleted" || echo "kept")"
echo "  - CloudWatch logs: $([ "$DELETE_LOGS" = "y" ] || [ "$DELETE_LOGS" = "Y" ] && echo "deleted" || echo "kept")"
echo "  - Local files: $([ "$DELETE_LOCAL" = "y" ] || [ "$DELETE_LOCAL" = "Y" ] && echo "deleted" || echo "kept")"
echo ""
echo "What was NOT deleted:"
SOMETHING_KEPT=0
if [ "$DELETE_AGENT" != "y" ] && [ "$DELETE_AGENT" != "Y" ]; then
    echo "  - AgentCore agent (still running, incurring compute costs)"
    SOMETHING_KEPT=1
fi
if [ "$DELETE_ECR" != "y" ] && [ "$DELETE_ECR" != "Y" ]; then
    echo "  - ECR repositories (incurring storage costs)"
    SOMETHING_KEPT=1
fi
if [ "$DELETE_LOGS" != "y" ] && [ "$DELETE_LOGS" != "Y" ]; then
    echo "  - CloudWatch log groups (minimal cost: ~$0.01/month)"
    SOMETHING_KEPT=1
fi
if [ "$DELETE_LOCAL" != "y" ] && [ "$DELETE_LOCAL" != "Y" ]; then
    echo "  - Local files (.bedrock_agentcore.yaml, api-gateway-config.env, Lambda files)"
    SOMETHING_KEPT=1
fi
echo "  - This cleanup script (cleanup.sh)"
echo "  - Agent source code (00_langgraph_agent.py, 01_agentcore_runtime.py, etc.)"
if [ $SOMETHING_KEPT -eq 0 ]; then
    echo ""
    echo "Note: All AWS resources and configuration files were deleted."
fi
echo ""
echo "Cost impact:"
echo "  - Before: ~$8-15/month (API Gateway + Lambda) + AgentCore compute + ECR storage"
if [ "$DELETE_AGENT" = "y" ] || [ "$DELETE_AGENT" = "Y" ]; then
    if [ "$DELETE_ECR" = "y" ] || [ "$DELETE_ECR" = "Y" ]; then
        echo "  - After: ~$0/month (all AWS resources deleted)"
    else
        echo "  - After: ~$0-1/month (only ECR storage remains)"
    fi
else
    echo "  - After: Variable (AgentCore agent still running)"
fi
echo ""
if [ "$DELETE_LOCAL" != "y" ] && [ "$DELETE_LOCAL" != "Y" ]; then
    echo "To delete remaining local files manually:"
    echo "  rm .bedrock_agentcore.yaml api-gateway-config.env"
    echo "  rm lambda_proxy.py lambda_function.zip lambda-policy.json lambda-trust-policy.json"
    echo ""
fi
echo "Manual AgentCore cleanup (if agentcore destroy failed):"
echo "  agentcore destroy --force"
echo ""
echo "To recreate the deployment, follow COMPLETE_DEPLOYMENT_GUIDE.md"
echo ""
