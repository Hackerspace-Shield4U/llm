import os
os.environ["OPENAI_API_KEY"] = "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"  # 실제 키

# 키가 잘 보이는지(비공개 세션이므로 print는 생략 가능)
assert os.getenv("OPENAI_API_KEY"), "환경변수 OPENAI_API_KEY 미설정"

# 간단 헬스체크: 클라이언트 생성
from openai import OpenAI
cli = OpenAI()
# 모델 접근권한 이슈가 있으면 여기서 에러가 날 수 있어요.

import json
import argparse
import re
from typing import List, Dict, Any, Tuple, Optional, Set
from urllib.parse import urlparse
from pydantic import BaseModel, Field
import time
import os
from openai import OpenAI

# ===== (선택) OpenAI - API 키 공란으로 둠 =====
#OPENAI_MODEL = "gpt-4o-mini"  # 예시 (필요 시 변경)
OPENAI_MODEL = "gpt-5"  # 예시 (필요 시 변경)



# 1) 환경변수에서 우선 읽고, 비었으면 기존 상수 사용
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL") or OPENAI_MODEL


def _get_openai_client():
    """
    OpenAI 클라이언트를 안전하게 생성하고, 실패 시 (None, reason) 반환.
    """
    if not _openai_available:
        return None, "openai 패키지가 설치되지 않았습니다. pip install openai"

    key = OPENAI_API_KEY
    if not key:
        return None, "OPENAI_API_KEY가 비어 있습니다. 환경변수 또는 상수에 키를 설정하세요."

    try:
        # v1 SDK는 보통 환경변수로 키를 읽습니다.
        # 여기서는 런타임에 키를 주입해도 되도록 env에 꽂아줍니다.
        os.environ["OPENAI_API_KEY"] = key
        client = OpenAI()  # api_key 인자를 생략하고 env 사용
        return client, None
    except Exception as e:
        return None, f"OpenAI 클라이언트 생성 실패: {e!r}"


try:
    _openai_available = True
except Exception:
    _openai_available = False
    OpenAI = None
# -------------------------
# 유틸
# -------------------------
def uniq(seq): # 리스트에서 중복을 제거하며 순서 보존
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def top_base(url: str) -> str: # URL에서 scheme://host/만 추출 (http://example.com/abc -> http://example.com/)
    try:
        u = urlparse(url)
        return f"{u.scheme}://{u.netloc}/"
    except Exception:
        return url

def suggest_templates_for(tag: str) -> List[str]: # nuclei 실행을 위한 템플릿 태그를 생성 (예: "tags:login")
    return [f"tags:{tag}"]

# -------------------------
# 감지기 (크롤러 JSON -> 원시 findings)
# -------------------------
ALLOW_TAGS_ALL = {
    "panel", "login",
    "wordpress", "wp-plugins", "cms", "joomla",
    "tech",
    "exposure", "info-leak", "logs", "debug",
    "osint", "osint-social", "listing"
}

def detect_panel_login(report: Dict[str, Any]) -> List[Dict[str, Any]]: # title, form, 링크를 분석해서 관리자 페이지(panel) 또는 로그인(login) 가능성을 탐지
    findings = []
    dom = report.get("dom", {})
    forms = dom.get("forms", []) or []
    title = (dom.get("title") or "").lower()
    visible_links = dom.get("visible_links", []) or []

    # 로그인 폼 추정
    login_forms = []
    for f in forms:
        inputs = set((f.get("inputs") or []))
        if "password" in inputs or {"username", "password"} & inputs:
            login_forms.append(f)

    # 후보 타겟
    candidates = []
    for href in visible_links:
        p = urlparse(href).path.lower()
        if any(k in p for k in ["/admin", "/wp-admin", "/wp-login.php", "/login", "/user/login", "/dashboard"]):
            candidates.append(href)

    # panel
    if "admin" in title or any("/admin" in urlparse(x).path.lower() for x in candidates):
        findings.append({
            "tag": "panel",
            "confidence": "high",
            "reason": "타이틀/링크에서 관리자 패턴 감지",
            "targets": uniq(candidates)[:10],
            "suggested_templates": suggest_templates_for("panel") + suggest_templates_for("login")
        })

    # login
    if login_forms or "login" in title or candidates:
        reasons = []
        for f in login_forms[:2]:
            reasons.append(f"로그인 폼(action={f.get('action')}, method={f.get('method')})")
        if "login" in title:
            reasons.append("타이틀 키워드 'login'")
        if candidates:
            reasons.append("로그인/패널 후보 링크 존재")
        targets = [f.get("action") for f in login_forms if f.get("action")] + candidates
        targets = uniq(targets)[:10]
        findings.append({
            "tag": "login",
            "confidence": "high" if login_forms else "medium",
            "reason": "; ".join(reasons) or "로그인 관련 신호",
            "targets": targets or [top_base(report.get("url", ""))],
            "suggested_templates": suggest_templates_for("login")
        })
    return findings

def detect_cms_stack(report: Dict[str, Any]) -> List[Dict[str, Any]]: # meta 태그, script/link 경로 등을 분석해 WordPress, Drupal, Jommla 같은 CMS 흔적을 탐지
    findings = []
    dom = report.get("dom", {})
    meta = dom.get("meta", {}) or {}
    scripts = dom.get("scripts", []) or []
    links = dom.get("links", []) or []

    # WordPress 흔적
    wp = ("generator" in meta and "wordpress" in str(meta.get("generator", "")).lower()) \
         or any("/wp-content/" in u or "/wp-includes/" in u for u in scripts + links)
    if wp:
        findings.append({
            "tag": "wordpress",
            "confidence": "high",
            "reason": "meta.generator 또는 /wp-content/ 경로",
            "targets": [top_base(report.get("url", ""))],
            "suggested_templates": suggest_templates_for("wordpress") + ["tags:wp", "tags:wp-plugin"]
        })
        wp_plugins = [u for u in scripts + links if "/wp-content/plugins/" in u]
        if wp_plugins:
            findings.append({
                "tag": "wp-plugins",
                "confidence": "medium",
                "reason": f"플러그인 경로 {len(wp_plugins)}개 노출",
                "targets": uniq(wp_plugins)[:20],
                "suggested_templates": ["tags:wp-plugins", "tags:wp-plugin"]
            })

    # 기타 CMS 흔적
    drupal = any("/sites/default/" in u for u in scripts + links)
    if drupal:
        findings.append({
            "tag": "cms",
            "confidence": "medium",
            "reason": "Drupal 패턴(/sites/default/) 감지",
            "targets": [top_base(report.get("url", ""))],
            "suggested_templates": ["tags:cms"]
        })
    joomla = any("joomla" in u.lower() for u in scripts + links)
    if joomla:
        findings.append({
            "tag": "joomla",
            "confidence": "medium",
            "reason": "리소스 경로에 'joomla'",
            "targets": [top_base(report.get("url", ""))],
            "suggested_templates": ["tags:joomla", "tags:cms"]
        })
    return findings

def detect_tech(report: Dict[str, Any]) -> List[Dict[str, Any]]: # fingerprints 필드에서 서버 기술 스택(nginx, php 등)을 추출
    fp = report.get("fingerprints", {}) or {}
    techs = fp.get("tech", []) or []
    if not techs:
        return []
    return [{
        "tag": "tech",
        "confidence": "medium",
        "reason": f"기술 스택: {', '.join(techs[:6])}",
        "targets": [top_base(report.get("url", ""))],
        "suggested_templates": suggest_templates_for("tech")
    }]

def detect_exposure(report: Dict[str, Any]) -> List[Dict[str, Any]]: # DOM의 주석/텍스트 단서에서 API 키, 로그, debug 메시지 등 민감 정보 노출을 탐지
    leaks = (report.get("dom", {}) or {}).get("comments_or_text_leaks", []) or []
    exposure, info_leak, logs, debug = [], [], [], []
    for l in leaks:
        t = (l.get("type") or "").lower()
        if t in ["api_key", "apikey", "secret", "token"]:
            exposure.append(l)
        elif t in ["stack", "warning", "traceback", "exception", "log"]:
            logs.append(l)
        elif t == "debug":
            debug.append(l)
        else:
            info_leak.append(l)
    out = []
    if exposure:
        out.append({
            "tag": "exposure",
            "confidence": "high",
            "reason": "민감 정보(API/Secret 등) 노출 단서",
            "targets": [top_base(report.get("url", ""))],
            "evidence": exposure[:5],
            "suggested_templates": ["tags:exposure", "tags:info-leak"]
        })
    if info_leak:
        out.append({
            "tag": "info-leak",
            "confidence": "medium",
            "reason": "주석/텍스트의 정보 누출 단서",
            "targets": [top_base(report.get("url", ""))],
            "evidence": info_leak[:5],
            "suggested_templates": ["tags:info-leak"]
        })
    if logs:
        out.append({
            "tag": "logs",
            "confidence": "medium",
            "reason": "스택트레이스/경고/로그 단서",
            "targets": [top_base(report.get("url", ""))],
            "evidence": logs[:5],
            "suggested_templates": ["tags:logs"]
        })
    if debug:
        out.append({
            "tag": "debug",
            "confidence": "medium",
            "reason": "DEBUG 플래그 단서",
            "targets": [top_base(report.get("url", ""))],
            "evidence": debug[:5],
            "suggested_templates": ["tags:debug"]
        })
    return out

def detect_osint(report: Dict[str, Any]) -> List[Dict[str, Any]]: # OSINT 노출 정보(이메일, 소셜 링크, 디렉토리 리스팅 등)를 탐지
    osint = report.get("osint_exposure", {}) or {}
    emails = osint.get("emails", []) or []
    socials = osint.get("socials", []) or []
    open_dirs = osint.get("open_directory_ui", []) or []
    out = []
    if emails:
        out.append({
            "tag": "osint",
            "confidence": "high",
            "reason": "보안/연락 이메일",
            "targets": [top_base(report.get("url", ""))],
            "evidence": {"emails": emails[:10]},
            "suggested_templates": ["tags:osint"]
        })
    if socials:
        out.append({
            "tag": "osint-social",
            "confidence": "high",
            "reason": "공식 소셜 링크",
            "targets": socials[:10],
            "evidence": {"socials": socials[:10]},
            "suggested_templates": ["tags:osint-social"]
        })
    if open_dirs:
        out.append({
            "tag": "listing",
            "confidence": "medium",
            "reason": "디렉토리 리스팅 UI",
            "targets": open_dirs[:10],
            "suggested_templates": ["tags:listing"]
        })
    return out

def build_raw_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]: # 위의 모든 감지기들을 순차적으로 실행하여 원시 findings 리스트를 만듦
    detectors = [detect_panel_login, detect_cms_stack, detect_tech, detect_exposure, detect_osint]
    findings = []
    for det in detectors:
        findings.extend(det(report))
    return findings

# -------------------------
# LLM 게이트 (보안 프롬프트 엔지니어링)
# -------------------------
class LLMFindingDecision(BaseModel): # 단일 finding에 대한 LLM 판정 구조체 (tag, severity, run 여부, rationale, references 등을 포함)
    tag: str
    looks_vulnerable: bool
    severity: str = Field(..., description="one of: none, low, medium, high, critical")
    rationale: str
    references: List[str] = Field(default_factory=list)  # ex) OWASP, CWE 링크 등
    run_template: bool = Field(..., description="nuclei 실행 가치 여부")

class LLMGateOutput(BaseModel): # LLM 전체 판정 결과 구조체(전체 위험도, 개별 decisions 리스트)
    overall_risk: str = Field(..., description="none|low|medium|high|critical")
    decisions: List[LLMFindingDecision]

SYSTEM_PROMPT = """You are a defensive security triage assistant.
RULES:
- If any URLs include known vulnerable patterns (e.g., /sqli/, /fi/, /phpinfo.php, ?page=), elevate severity to 'high' AND set run_template=true.
- Do NOT fabricate data or payloads, but do suggest scanner template tags such as 'sqli', 'lfi', or 'debug-info-leak' if patterns match known vulnerability classes.
- Output STRICT JSON only, no markdown, no commentary.
- If evidence suggests sensitive info exposure (e.g., API keys, secrets, debug logs), elevate risk.
- If the input includes potentially sensitive endpoints (e.g., login.php, admin/, debug/, test/, api/token), increase severity.
- If the input contains SQL keywords (e.g., SELECT, UNION, WHERE) or suspect query params (e.g., ?id=, ?q=), flag as 'medium' or higher.
- NEVER attempt active exploitation or generate attack payloads.
- Base your analysis ONLY on the provided JSON; do NOT fabricate.
- Cite public references (e.g., OWASP, CWE) in 'references' when relevant.
- If the LLM detects known vulnerable paths (e.g., /sqli/, /fi/?page=, /phpinfo.php), and severity is high, then set run_template=true regardless of raw finding presence.
- In such cases, recommend generic scanner tags (e.g., 'sqli', 'lfi', 'debug-info-leak') in suggested_templates.
- Do NOT generate payloads or active tests.
"""

USER_PROMPT_TEMPLATE = """Input JSON (from crawler):
{crawler_json}

Task:
For each finding candidate below, decide if it looks vulnerable in a way that justifies running a nuclei template. Consider severity (none|low|medium|high|critical) and set run_template true/false.

Candidates:
{candidates_json}

Output JSON schema:
{{
  "overall_risk": "none|low|medium|high|critical",
  "decisions": [
    {{
      "tag": "<string>",
      "looks_vulnerable": <true|false>,
      "severity": "none|low|medium|high|critical",
      "rationale": "<short reason>",
      "references": ["<optional refs>"],
      "run_template": <true|false>
    }}
  ]
}}
"""

# --- 모델별 파라미터 호환 처리: gpt-5 계열은 temperature/top_p 등 미지원 ---
def _sampling_supported(model: str) -> bool:
    return not model.lower().startswith("gpt-5")

def _postprocess_and_fill_missing(raw_findings: List[Dict[str, Any]], llm_out: Dict[str, Any]) -> LLMGateOutput:
    """
    LLM이 일부 tag만 판단했을 경우, 누락된 tag는 conservative default로 채운다.
    """
    try:
        parsed = LLMGateOutput(**llm_out)
    except Exception as e:
        raise ValueError(f"LLM output schema validation failed: {e}")

    decided_tags = {d.tag for d in parsed.decisions}
    all_tags = [f["tag"] for f in raw_findings]
    missing = [t for t in all_tags if t not in decided_tags]

    if missing:
        for t in missing:
            parsed.decisions.append(LLMFindingDecision(
                tag=t,
                looks_vulnerable=False,
                severity="low",
                rationale="no decision returned; defaulting to conservative low/no-run",
                references=[],
                run_template=False
            ))
        # overall_risk 재계산(가장 높은 severity)
        sev_rank = {"none":0,"low":1,"medium":2,"high":3,"critical":4}
        max_sev = "none"
        for d in parsed.decisions:
            if sev_rank.get(d.severity, 0) > sev_rank.get(max_sev, 0):
                max_sev = d.severity
        parsed.overall_risk = max_sev

    return parsed


def call_llm_gate(
    crawler_report: Dict[str, Any],
    raw_findings: List[Dict[str, Any]],
    max_candidates_per_call: Optional[int] = None  # 너무 큰 입력이면 분할 (기본: 전체 1회)
) -> Optional[LLMGateOutput]:
    """
    OpenAI API로 findings의 스캔 가치/심각도를 판정.
    - 모델별 파라미터 호환 처리(예: gpt-5*는 temperature/top_p 미지원)
    - JSON 파싱 견고화 및 누락 태그 보정
    - 실패 시 None 반환(휴리스틱으로 폴백)
    """
    client, why = _get_openai_client()
    if client is None:
        print(f"[LLM GATE FALLBACK] {why}")
        return None

    # 후보 분할(옵션) — 기본은 전체 한 번에
    batches: List[List[Dict[str, Any]]] = []
    if max_candidates_per_call and max_candidates_per_call > 0:
        for i in range(0, len(raw_findings), max_candidates_per_call):
            batches.append(raw_findings[i:i+max_candidates_per_call])
    else:
        batches = [raw_findings]

    # 각 배치를 호출 후 병합
    merged_decisions: List[LLMFindingDecision] = []
    overall_max = "none"
    sev_rank = {"none":0,"low":1,"medium":2,"high":3,"critical":4}

    for batch_idx, batch in enumerate(batches):
        user_prompt = USER_PROMPT_TEMPLATE.format(
            crawler_json=json.dumps(crawler_report, ensure_ascii=False, indent=2),
            candidates_json=json.dumps(batch, ensure_ascii=False, indent=2),
        )

        # gpt-5*는 sampling 파라미터 제거
        kwargs = {}
        # if _sampling_supported(OPENAI_MODEL):
        #     kwargs["temperature"] = 0.2

        last_err = None
        for attempt in range(2):
            try:
                resp = client.chat.completions.create(
                    model=OPENAI_MODEL,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ],
                    **kwargs
                )
                text = resp.choices[0].message.content.strip()
                m = re.search(r"\{.*\}\s*$", text, re.S)
                raw_json = m.group(0) if m else text
                data = json.loads(raw_json)
                parsed = _postprocess_and_fill_missing(batch, data)

                # 병합
                merged_decisions.extend(parsed.decisions)
                if sev_rank.get(parsed.overall_risk, 0) > sev_rank.get(overall_max, 0):
                    overall_max = parsed.overall_risk
                break  # 배치 성공했으면 다음 배치로
            except Exception as e:
                last_err = e
                time.sleep(0.5)
        else:
            print(f"[LLM GATE FALLBACK] batch {batch_idx} failed: {type(last_err).__name__}: {last_err}")
            return None  # 배치 중 하나라도 실패하면 휴리스틱으로 폴백

    # 최종 병합 결과(동일 tag 중복 시 마지막값 유지)
    final_by_tag: Dict[str, LLMFindingDecision] = {}
    for d in merged_decisions:
        final_by_tag[d.tag] = d
    final = LLMGateOutput(overall_risk=overall_max, decisions=list(final_by_tag.values()))
    return final

# -------------------------
# 휴리스틱 게이트 (LLM 불가 시)
# -------------------------
SEV_ORDER = ["none", "low", "medium", "high", "critical"]

def heuristic_gate(raw_findings: List[Dict[str, Any]]) -> LLMGateOutput:
    decisions = []
    # 단순 정책: exposure > panel/login > wp-plugins > wordpress > tech > others
    for f in raw_findings:
        tag = f["tag"]
        sev = "low"
        run = False

        if tag == "exposure":
            sev, run = "high", True
        elif tag in ("panel", "login"):
            sev, run = "medium", True
        elif tag in ("wp-plugins",):
            sev, run = "medium", True
        elif tag in ("wordpress", "cms", "joomla"):
            sev, run = "low", True
        elif tag in ("logs", "debug", "info-leak"):
            sev, run = "medium", True
        elif tag in ("tech", "osint", "osint-social", "listing"):
            sev, run = "low", False  # 정보성

        decisions.append(LLMFindingDecision(
            tag=tag,
            looks_vulnerable=run,
            severity=sev,
            rationale="heuristic decision (no-LLM)",
            references=[],
            run_template=run
        ))

    # overall_risk = 최고 등급
    max_sev = "none"
    for d in decisions:
        if SEV_ORDER.index(d.severity) > SEV_ORDER.index(max_sev):
            max_sev = d.severity

    return LLMGateOutput(overall_risk=max_sev, decisions=decisions)

# -------------------------
# nuclei 실행/미실행 분리
# -------------------------
def split_to_run_skip(raw_findings: List[Dict[str, Any]], # findings를 to_run(스캐닝 실행)과 to_skip(실행 제외)으로 나눈다.
                      gate: LLMGateOutput,
                      allow_tags: Set[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    to_run, to_skip = [], []
    # tag -> run_template 맵
    runmap = {d.tag: d.run_template for d in gate.decisions}
    sevmap = {d.tag: d.severity for d in gate.decisions}
    ratemap = {d.tag: d.rationale for d in gate.decisions}

    for f in raw_findings:
        tag = f["tag"]
        f["llm_severity"] = sevmap.get(tag, "low")
        f["llm_rationale"] = ratemap.get(tag, "decision missing")
        if tag in allow_tags and runmap.get(tag, False):
            to_run.append(f)
        else:
            to_skip.append(f)
    return to_run, to_skip

import os
import json
import argparse
from typing import Dict, Any, Optional

# ---- 공통 설정 ----
DEFAULT_ALLOW = ",".join(sorted(ALLOW_TAGS_ALL)) # 허용되는 태그 전체 목록을 기본값으로 문자열로 보관

def in_notebook() -> bool:
    """Jupyter/Colab에서 실행 중인지 판별."""
    try:
        from IPython import get_ipython  # noqa
        return True
    except Exception:
        return False

def run_pipeline_from_report(report: Dict[str, Any], allow: str = DEFAULT_ALLOW) -> Dict[str, Any]:
    allow_tags = set([t.strip() for t in (allow or "").split(",") if t.strip()])
    raw_findings = build_raw_findings(report)

    # 🔥 완화 정책: 너무 findings가 적으면 LLM 시도 유도
    if len(raw_findings) == 0:
        print("[ℹ️] Finding 없음: LLM 기반 탐색 시도 중...")
        dummy_finding = {
            "tag": "minimal-check",
            "confidence": "low",
            "reason": "No raw finding; sending dummy input to LLM for conservative check",
            "targets": [top_base(report.get("url", ""))],
            "suggested_templates": []
        }
        raw_findings = [dummy_finding]

    gate = call_llm_gate(report, raw_findings) or heuristic_gate(raw_findings)
    to_run, to_skip = split_to_run_skip(raw_findings, gate, allow_tags)
    return {"overall_risk": gate.overall_risk, "to_run": to_run, "to_skip": to_skip}


def run_pipeline_from_file(crawler_json_path: str, allow: str = DEFAULT_ALLOW) -> Dict[str, Any]:
    """파일 경로로 파이프라인 실행."""
    with open(crawler_json_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    return run_pipeline_from_report(report, allow=allow)

def main(crawler_json: Optional[str] = None,
         allow: str = DEFAULT_ALLOW,
         report_obj: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    공통 진입점:
    - 노트북에서는 main(report_obj=...) 또는 main(crawler_json=...)로 직접 호출
    - .py CLI에서는 argparse로 값을 받아 main(crawler_json=...) 호출
    """
    if report_obj is not None:
        return run_pipeline_from_report(report_obj, allow=allow)
    if crawler_json:
        return run_pipeline_from_file(crawler_json, allow=allow)
    raise ValueError("main()에는 crawler_json(파일 경로) 또는 report_obj(dict) 중 하나가 필요합니다.")

def main_cli() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("crawler_json", help="crawler report json path")
    ap.add_argument("--allow", type=str, default=DEFAULT_ALLOW,
                    help="comma-separated tags to allow")
    ap.add_argument("--author", type=str, default="ksko", help="YAML author metadata")
    ap.add_argument("--id-prefix", type=str, default="auto-gen", help="YAML id prefix")
    ap.add_argument("--out", type=str, help="YAML 파일 저장 경로 (예: nuclei_auto.yaml)")
    ap.add_argument("--print-json", action="store_true", help="JSON 결과도 출력")
    args = ap.parse_args()

    # 분석 파이프라인 실행
    out = main(crawler_json=args.crawler_json, allow=args.allow)

    if args.print_json:
        print(json.dumps(out, ensure_ascii=False, indent=2))

    # nuclei YAML 생성
    yaml_out = findings_to_nuclei_yaml(
        out,
        base_id_prefix=args.id_prefix,
        author=args.author
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(yaml_out)
        print(f"[✓] YAML 저장 완료: {args.out}")
    else:
        print(yaml_out)

import re, yaml, json
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

def _to_rel_path(u: str) -> str:
    if re.match(r"^https?://", u, re.I):
        p = urlparse(u).path or "/"
        if not p.startswith("/"):
            p = "/" + p
        return "{{BaseURL}}" + p
    if not u.startswith("/"):
        u = "/" + u
    return "{{BaseURL}}" + u

def _only_urls(refs: List[str]) -> List[str]:
    return [r for r in (refs or []) if r.startswith("http")]

def _basic_matchers_for(tag: str):
    tag = (tag or "").lower()
    if tag in ("panel", "login"):
        return {
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 302, 401, 403]},
                {"type": "word", "words": ["login", "admin", "sign in"], "condition": "or", "part": "body"}
            ]
        }
    if tag in ("wordpress", "wp-plugins"):
        return {
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200, 302]},
                {"type": "word", "words": ["/wp-content/", "WordPress"], "condition": "or", "part": "body"}
            ]
        }
    if tag in ("exposure", "logs", "listing"):
        return {
            "matchers-condition": "or",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "words": ["Index of /", "Traceback", "Warning:"], "part": "body"}
            ]
        }
    return {"matchers": [{"type": "status", "status": [200, 302, 401, 403]}]}

def findings_to_nuclei_yaml(
    pipeline_out: Dict[str, Any],
    base_id_prefix: str = "auto-gen",
    author: str = "ksko",
    add_metadata: Optional[Dict[str, Any]] = None
) -> str:
    add_metadata = add_metadata or {"source": "auto-pipeline"}
    findings = pipeline_out.get("to_run", []) or []
    yamls = []
    for idx, f in enumerate(findings, 1):
        tag = f.get("tag", "unknown")
        sev = (f.get("llm_severity") or "low").lower()
        rationale = f.get("llm_rationale") or f.get("reason") or ""
        refs = _only_urls(f.get("suggested_templates") or [])
        targets = f.get("targets") or []

        paths, seen = [], set()
        for t in targets:
            p = _to_rel_path(str(t))
            if p not in seen:
                seen.add(p)
                paths.append(p)

        tpl = {
            "id": f"{base_id_prefix}-{tag}-{idx}",
            "info": {
                "name": f"Auto-detected {tag}",
                "author": author,
                "severity": sev,
                "description": rationale,
                "reference": refs,
                "tags": [tag],
                "metadata": {**add_metadata, "rule": tag}
            },
            "http": []
        }
        if paths:
            http_block = {
                "method": "GET",
                "path": paths,
                "redirects": True,
                "max-redirects": 2,
                "stop-at-first-match": True,
            }
            http_block.update(_basic_matchers_for(tag))
            tpl["http"].append(http_block)
        yamls.append(tpl)
    return yaml.dump_all(yamls, sort_keys=False, allow_unicode=True)

if __name__ == "__main__":

    main_cli()