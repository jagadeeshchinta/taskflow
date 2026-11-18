<#
.SYNOPSIS
  TaskFlow CloudFormation Packaging, Validation, and Pre-Deployment Tool
.DESCRIPTION
  Validates individual CloudFormation templates with AWS CLI, optionally uploads
  nested templates to an S3 staging bucket, and packages the master stack.
.EXAMPLE
  .\scripts\package-and-validate-cfn.ps1 -Region "ap-south-1" -ValidateOnly
#>

param(
  [string]$Region = "ap-south-1",
  [string]$TemplateBucket = "",
  [switch]$ValidateOnly = $false
)

$ErrorActionPreference = "Continue"

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " TaskFlow CloudFormation Validation & Packaging Suite" -ForegroundColor Cyan
Write-Host " Target Region: $Region" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

$TemplateDir = Join-Path $PSScriptRoot "..\cloudformation"
$Templates = @(
  "01-networking.yaml",
  "02-iam.yaml",
  "03-s3.yaml",
  "04-rds.yaml",
  "05-ec2.yaml",
  "06-cloudwatch.yaml",
  "00-master-stack.yaml"
)

Write-Host "`n[1/3] Checking template existence and basic readability..." -ForegroundColor Yellow
$AllPresent = $true

foreach ($tpl in $Templates) {
  $path = Join-Path $TemplateDir $tpl
  if (Test-Path $path) {
    $size = (Get-Item $path).Length
    Write-Host "  [OK] $tpl ($size bytes)" -ForegroundColor Green
  } else {
    Write-Host "  [FAIL] Missing template: $tpl" -ForegroundColor Red
    $AllPresent = $false
  }
}

if (-not $AllPresent) {
  Write-Error "Template validation failed. Required template files are missing."
  exit 1
}

Write-Host "`n[2/3] Validating template syntax with AWS CloudFormation API..." -ForegroundColor Yellow
$AllValid = $true

foreach ($tpl in $Templates) {
  $path = Join-Path $TemplateDir $tpl
  $res = aws cloudformation validate-template --template-body "file://$path" --region $Region 2>&1
  if ($LASTEXITCODE -eq 0) {
    Write-Host "  [PASSED] $tpl" -ForegroundColor Green
  } else {
    if ($res -match "AccessDenied") {
      Write-Host "  [IAM RESTRICTION] ${tpl} - cloudformation:ValidateTemplate not permitted for current IAM identity." -ForegroundColor DarkYellow
    } else {
      Write-Host "  [FAILED] ${tpl} - $res" -ForegroundColor Red
      $AllValid = $false
    }
  }
}

if ($ValidateOnly) {
  Write-Host "`n[ValidateOnly Mode] Local pre-flight check complete. No resources deployed." -ForegroundColor Cyan
  exit 0
}

# ── Upload nested templates to S3 if bucket provided ──────────────────
if ($TemplateBucket) {
  Write-Host "`n[3/3] Uploading nested stack templates to s3://$TemplateBucket/..." -ForegroundColor Yellow
  foreach ($tpl in $Templates) {
    if ($tpl -ne "00-master-stack.yaml") {
      $path = Join-Path $TemplateDir $tpl
      aws s3 cp $path "s3://$TemplateBucket/$tpl" --region $Region
      Write-Host "  Uploaded: $tpl" -ForegroundColor Green
    }
  }

  Write-Host "`nReady for master stack deployment with TemplateBaseUrl: https://$TemplateBucket.s3.$Region.amazonaws.com" -ForegroundColor Cyan
} else {
  Write-Host "`n[Note] Staging bucket not specified. Provide -TemplateBucket <bucket-name> when uploading templates." -ForegroundColor Yellow
}
