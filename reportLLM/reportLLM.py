# llm_report.py
# ----------------------------------------------------------------
# Jupyter Notebook 셀들을 하나의 실행 가능한 Python 스크립트로 변환한 파일입니다.
# ----------------------------------------------------------------

import os
import sys
import json
import datetime
import subprocess
from getpass import getpass
from typing import Any, Dict, List

# --- 1. 의존성 설치 ---
# 스크립트 실행에 필요한 라이브러리를 확인하고 설치합니다.

def pip_install(pkg: str):
    """지정된 패키지를 pip를 사용하여 설치합니다."""
    try:
        __import__(pkg.split('>')[0].split('=')[0])
    except ImportError:
        print(f'Installing missing package: {pkg}')
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg])

# 필요한 라이브러리 목록
REQUIRED_PACKAGES = [
    'openai>=1.40.0',
    'matplotlib>=3.7.0',
    'pandas',
    'numpy'
]

for package in REQUIRED_PACKAGES:
    pip_install(package)

# 라이브러리 임포트
from openai import OpenAI
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


# --- 2. 기본 설정 및 LLM 함수 정의 ---

# 사용할 OpenAI 모델 정의
MODEL = os.getenv("OPENAI_MODEL_REPORT", "gpt-4o")

# LLM이 분류 기준으로 사용할 전략 태그 목록
ALLOWED_TAGS = [
    "panel", "login",
    "wordpress", "joomla", "wp-plugins", "cms",
    "tech",
    "exposure", "info-leak", "logs", "debug",
    "osint", "osint-social", "listing",
    "Miscellaneous" # 기타
]

def build_report_schema() -> Dict[str, Any]:
    """LLM이 생성할 보고서 데이터의 JSON 스키마를 정의합니다."""
    return {
        "name": "security_report_v3",
        "description": "Nuclei 스캔 결과를 분석하여 생성된 상세 보안 점검 보고서",
        "parameters": {
            "type": "object",
            "required": ["executive_summary", "severity_summary", "detailed_findings"],
            "properties": {
                "executive_summary": {
                    "type": "object",
                    "properties": {
                        "target_domain": {"type": "string"},
                        "total_findings": {"type": "integer"},
                        "highest_severity": {"type": "string"},
                        "overall_risk_level": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"]},
                        "summary_text": {"type": "string"}
                    }
                },
                "severity_summary": {
                    "type": "object",
                    "properties": {
                        "critical": {"type": "integer"}, "high": {"type": "integer"},
                        "medium": {"type": "integer"}, "low": {"type": "integer"}, "info": {"type": "integer"}
                    }
                },
                "detailed_findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["vulnerability_name", "severity", "exploitability", "strategic_tag", "description", "impact", "recommendation", "affected_url"],
                        "properties": {
                            "vulnerability_name": {"type": "string"},
                            "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                            "exploitability": {"type": "string", "enum": ["Easy", "Moderate", "Difficult"]},
                            "strategic_tag": {"type": "string", "enum": ALLOWED_TAGS},
                            "description": {"type": "string"},
                            "impact": {"type": "string"},
                            "recommendation": {"type": "string"},
                            "affected_url": {"type": "string"}
                        }
                    }
                }
            }
        }
    }

def generate_report_data_with_llm(nuclei_content: str) -> Dict[str, Any]:
    """Nuclei 스캔 결과를 받아 LLM을 통해 구조화된 보고서 데이터를 생성합니다."""
    SYSTEM_PROMPT = f"""
    당신은 최고의 사이버 보안 분석가입니다. Nuclei 스캔 결과를 분석하여 비전문가도 이해할 수 있는 명확한 보안 보고서를 생성하세요.

    **보고서 생성 가이드라인:**
    1.  **핵심 요약 (Executive Summary):** 반드시 `target_domain`, `total_findings` 등의 필드를 포함하는 **객체(object)**로 생성해야 합니다.
    2.  **상세 분석 (Detailed Findings):** 각 취약점에 대해 아래 항목을 반드시 포함하여 분석하세요.
        - **strategic_tag (전략 태그):** 각 취약점이 아래 [허용 태그] 목록 중 어떤 것에 가장 가까운지 분류하세요. 예를 들어 'exposed-panels.yaml'은 'panel' 태그에 해당합니다. 적절한 태그가 없으면 'Miscellaneous'를 사용하세요.
        - **exploitability (공격 가능성):** 'Easy', 'Moderate', 'Difficult' 중 하나로 분류하세요.
        - **Description, Impact, Recommendation:** 비전문가가 이해하기 쉽게 작성하세요.
    3.  **출력 형식:** 반드시 `security_report_v3` 함수의 인자 형식에 맞는 JSON 객체 하나만 반환해야 합니다.

    [허용 태그]
    {', '.join(ALLOWED_TAGS)}
    """
    client = OpenAI()
    report_tool_schema = build_report_schema()
    
    print("🚀 OpenAI API에 상세 보고서 생성을 요청합니다...")
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"아래 Nuclei 스캔 결과를 분석하여 보고서를 생성해 주세요:\\n\\n---\\n{nuclei_content}"}
            ],
            tools=[{"type": "function", "function": report_tool_schema}],
            tool_choice={"type": "function", "function": {"name": "security_report_v3"}},
            temperature=0.1
        )
        tool_call = resp.choices[0].message.tool_calls[0]
        report_data = json.loads(tool_call.function.arguments)
        print("✨ LLM으로부터 상세 분석 데이터를 성공적으로 받았습니다.")
        return report_data
    except Exception as e:
        print(f"🚨 LLM 호출 중 오류가 발생했습니다: {e}")
        return None

# --- 3. 데이터 시각화 함수 ---

def create_all_tags_summary_chart(all_tags: list, findings_data: list, output_path: str):
    """전체 태그의 취약점 발견 건수를 시각화합니다."""
    tag_counts = {tag: 0 for tag in all_tags}
    for item in findings_data:
        tag = item.get('strategic_tag')
        if tag in tag_counts:
            tag_counts[tag] += 1
            
    df = pd.DataFrame(list(tag_counts.items()), columns=['tag', 'count']).sort_values(by='count', ascending=False)
    colors = ['#ef9a9a' if count > 0 else '#c8e6c9' for count in df['count']]
    
    plt.figure(figsize=(12, 8))
    bars = plt.bar(df['tag'], df['count'], color=colors)
    
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            plt.text(bar.get_x() + bar.get_width()/2, height + 0.1, f'{int(height)}', ha='center')

    plt.title('Summary of All Scanned Tags', fontsize=16, fontweight='bold')
    plt.ylabel('Number of Vulnerabilities Found')
    plt.xlabel('Strategic Tag')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"📊 전체 태그 점검 현황 차트가 '{output_path}' 파일로 저장되었습니다.")
    plt.close()

def create_tag_severity_chart(findings_data: list, output_path: str):
    """전략 태그별로 심각도 분포를 보여주는 누적 막대 차트를 생성합니다."""
    if not findings_data:
        print("📊 데이터가 없어 태그별 심각도 차트를 생성하지 않습니다.")
        return

    df = pd.DataFrame(findings_data)
    tag_severity_counts = df.groupby(['strategic_tag', 'severity']).size().unstack(fill_value=0)
    tag_severity_counts = tag_severity_counts[tag_severity_counts.sum(axis=1) > 0]
    
    if tag_severity_counts.empty:
        print("📊 취약점이 발견된 태그가 없어 상세 분석 차트를 생성하지 않습니다.")
        return

    severity_order = [s for s in ['Critical', 'High', 'Medium', 'Low', 'Info'] if s in tag_severity_counts.columns]
    tag_severity_counts = tag_severity_counts[severity_order]

    ax = tag_severity_counts.plot(
        kind='bar', stacked=True, figsize=(12, 8),
        color={'Critical': '#d62728', 'High': '#ff7f0e', 'Medium': '#ffbb78', 'Low': '#1f77b4', 'Info': '#aec7e8'}
    )

    plt.title('Detailed Analysis of Tags with Findings', fontsize=16, fontweight='bold')
    plt.ylabel('Number of Findings by Severity')
    plt.xlabel('Strategic Tag')
    plt.xticks(rotation=45, ha='right')
    plt.legend(title='Severity')
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"� 태그별 심각도 분포 차트가 '{output_path}' 파일로 저장되었습니다.")
    plt.close()

# --- 4. 최종 보고서 생성 함수 ---

def render_final_report(title: str, check_date: str, all_tags: list, report_data: dict, chart_paths: dict, output_path: str):
    """개선된 템플릿과 시각화 자료로 최종 보고서를 생성합니다."""
    summary = report_data.get('executive_summary', {})
    findings = report_data.get('detailed_findings', [])
    target_domain = summary.get('target_domain', 'N/A') if isinstance(summary, dict) else "N/A"

    md = f"# 🛡️ {title}\n\n"
    md += f"| **점검 대상** | {target_domain} |\n"
    md += f"| :--- | :--- |\n"
    md += f"| **점검 일시** | {check_date} |\n\n"
    md += "---\n\n"
    
    md += "## 1. 개요 (Executive Summary)\n\n"
    if isinstance(summary, dict):
        md += f"> {summary.get('summary_text', '요약 정보 없음')}\n\n"
        md += f"- **총 발견 항목:** {summary.get('total_findings', len(findings))} 건\n"
        md += f"- **종합 위험 등급:** **{summary.get('overall_risk_level', 'N/A')}**\n\n"

    md += "## 2. 점검 결과 요약\n\n"
    md += "### 2.1. 전체 태그 점검 현황\n\n"
    md += "> **설명:** 이번 점검에 사용된 모든 전략 태그와 태그별 취약점 발견 건수입니다.\n\n"
    
    tag_counts = {tag: 0 for tag in all_tags}
    for item in findings:
        tag = item.get('strategic_tag')
        if tag in tag_counts:
            tag_counts[tag] += 1
            
    md += "| 전략 태그 (Strategic Tag) | 발견된 취약점 수 | 상태 |\n"
    md += "| :--- | :---: | :---: |\n"
    for tag, count in sorted(tag_counts.items()):
        status = "🔴 Finding" if count > 0 else "🟢 Clear"
        md += f"| `{tag}` | **{count}** | {status} |\n"
    md += "\n"
    md += f"![전체 태그 점검 현황]({os.path.basename(chart_paths.get('all_tags_summary', ''))})\n\n"
    
    md += "### 2.2. 취약점 발견 태그 상세 분석\n\n"
    md += "> **설명:** 취약점이 발견된 태그들만 모아 각 태그에 어떤 심각도의 취약점들이 포함되어 있는지 보여줍니다.\n\n"
    md += f"![태그별 심각도 분포]({os.path.basename(chart_paths.get('tag_severity', ''))})\n\n"
    
    md += "---\n\n"
    md += "## 3. 상세 분석 결과\n\n"
    
    if not findings:
        md += "✅ 발견된 주요 보안 취약점이 없습니다.\n"
    else:
        severity_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'Info'), 0), reverse=True)
        for i, item in enumerate(sorted_findings):
            md += f"### 3.{i+1} {item.get('vulnerability_name', 'N/A')}\n\n"
            md += f"| 심각도 | 공격 가능성 | 전략 태그 |\n"
            md += f"| :---: | :---: | :--- |\n"
            md += f"| `{item.get('severity', 'N/A')}` | `{item.get('exploitability', 'N/A')}` | `{item.get('strategic_tag', 'N/A')}` |\n\n"
            md += f"- **발견 위치:** `{item.get('affected_url', 'N/A')}`\n\n"
            md += f"**상세 설명**\n{item.get('description', 'N/A')}\n\n"
            md += f"**예상 피해**\n{item.get('impact', 'N/A')}\n\n"
            md += f"**권고 조치**\n{item.get('recommendation', 'N/A')}\n\n---\n"
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md)
    
    print(f"📄 업그레이드된 최종 보고서가 '{output_path}' 파일로 성공적으로 생성되었습니다.")

# --- 5. 메인 실행 함수 ---

def main():
    """스크립트의 메인 실행 로직"""
    # API 키 설정
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print('Enter your OpenAI API key (session only; not saved to disk):')
        api_key = getpass('OPENAI_API_KEY: ')
        os.environ['OPENAI_API_KEY'] = api_key
    
    masked = 'SET (sk-***' + os.environ['OPENAI_API_KEY'][-6:] + ')'
    print('OPENAI_API_KEY:', masked)

    # 입력 파일 경로 설정
    input_file = "nuclei_scan_demo.md"
    
    # 입력 파일이 없을 경우 예시 파일 생성
    if not os.path.exists(input_file):
        print(f"'{input_file}'을 찾을 수 없습니다. 예시 파일을 생성합니다.")
        mock_nuclei_results = """
# Nuclei Scan Results for test-target.com
### [exposed-panels] - Exposed Admin Panel
- Template ID: exposed-panels.yaml
- Severity: high
- Host: https://test-target.com
- Matched At: https://test-target.com/admin/login.php
- Tags: tech,panel,login
### [wordpress-login-enum] - WordPress Username Enumeration
- Template ID: wordpress-username-enumeration.yaml
- Severity: medium
- Host: https://test-target.com
- Matched At: https://test-target.com/?author=1
- Tags: wordpress,wp,cve,recon
### [wordpress-version] - WordPress Version Detected
- Template ID: wordpress-version-detection.yaml
- Severity: info
- Host: https://test-target.com
- Matched At: https://test-target.com/feed/
- Tags: tech,wordpress,wp
        """
        with open(input_file, "w", encoding="utf-8") as f:
            f.write(mock_nuclei_results)
    
    # 보고서 생성 프로세스 시작
    with open(input_file, "r", encoding="utf-8") as f:
        nuclei_content = f.read()
    print(f"'{input_file}' 파일 내용을 읽었습니다.")

    now = datetime.datetime.now()
    check_date_str = now.strftime("%Y-%m-%d %H:%M:%S")
    report_title = "test-target.com 웹 애플리케이션 정기 보안 점검"

    report_data = generate_report_data_with_llm(nuclei_content)

    if report_data:
        chart_paths = {
            "all_tags_summary": "all_tags_summary.png",
            "tag_severity": "tag_severity_chart.png",
        }
        create_all_tags_summary_chart(ALLOWED_TAGS, report_data['detailed_findings'], chart_paths['all_tags_summary'])
        create_tag_severity_chart(report_data['detailed_findings'], chart_paths['tag_severity'])

        report_file = "final_report.md"
        render_final_report(report_title, check_date_str, ALLOWED_TAGS, report_data, chart_paths, report_file)

        print("\n--- 최종 보고서 미리보기 ---")
        with open(report_file, "r", encoding="utf-8") as f:
            print(f.read())
    else:
        print("\n보고서 데이터 생성에 실패하여 프로세스를 중단합니다.")

if __name__ == "__main__":
    main()
