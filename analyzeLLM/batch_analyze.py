import os
import glob
import analyzeLLM

# 처리할 디렉토리 경로
input_dir = "./tmp"
output_dir = "./yaml_output"
os.makedirs(output_dir, exist_ok=True)

# 디렉토리 내 .json 파일 모두 처리
json_files = glob.glob(os.path.join(input_dir, "*.json"))

for json_path in json_files:
    # 파일 이름 추출 및 출력 파일명 생성
    base_name = os.path.splitext(os.path.basename(json_path))[0]
    output_yaml_path = os.path.join(output_dir, f"nuclei_{base_name}.yaml")

    print(f"\n[🔍] Processing: {json_path}")
    
    # analyzeLLM 모듈의 main 호출
    output = analyzeLLM.main(crawler_json=json_path)

    # YAML 생성
    yaml_str = analyzeLLM.findings_to_nuclei_yaml(
        output,
        base_id_prefix="auto-gen",
        author="ksko"
    )

    # 파일 저장
    with open(output_yaml_path, "w", encoding="utf-8") as f:
        f.write(yaml_str)

    print(f"[✓] YAML saved to: {output_yaml_path}")

    # JSON 출력 옵션 (선택)
    print("[🧾] JSON 결과 요약:")
    import json
    print(json.dumps(output, indent=2, ensure_ascii=False))
