"""
自动审查管理器
提供审查技能映射、审查报告保存和批量审查功能
使用LLM-as-a-Judge方式，确保每份报告都严格按照审查技能规范执行审查
"""
import os
import re
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from ..llm_client import LLMClient


class AutoAuditManager:
    """自动审查管理器"""
    
    REPORT_TYPE_SKILL_MAP = {
        'asset': 'asset_report_audit',
        'alert': 'alert_report_audit',
        'event': 'event_report_audit',
        'vuln': 'vuln_report_audit'
    }

    REPORT_TYPE_DIR_MAP = {
        'asset': 'asset_report',
        'alert': 'alert_report',
        'event': 'event_report',
        'vuln': 'vuln_report'
    }
    
    REPORT_TYPE_NAME_MAP = {
        'asset': '资产',
        'alert': '告警',
        'event': '事件',
        'vuln': '漏洞'
    }
    
    def __init__(self, base_dir: str = None, run_date: str = None):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        self.base_dir = base_dir
        self.outputs_dir = os.path.join(base_dir, 'outputs')
        # 运行日期：用于审查报告按日期归档，格式 YYYYMMDD_HHMMSS 或 YYYYMMDD
        self.run_date = run_date or datetime.now().strftime('%Y%m%d_%H%M%S')
        # 审查报告输出根目录
        self._batch_audit_root = os.path.join(self.outputs_dir, 'batch_audit')
        # 本次运行的审查报告目录（含日期子目录）
        self.batch_audit_dir = os.path.join(self._batch_audit_root, self.run_date)
        # 原始报告来源目录（ai_test_agent 分类，由 run_ai_test_agent.py 生成）
        self.ai_test_agent_dir = os.path.join(self.outputs_dir, 'ai_test_agent')
        self._create_audit_dirs()
        self.llm_client = LLMClient()
    
    def _create_audit_dirs(self) -> None:
        for report_type, dir_name in self.REPORT_TYPE_DIR_MAP.items():
            audit_dir = os.path.join(self.batch_audit_dir, dir_name)
            os.makedirs(audit_dir, exist_ok=True)
        # 综合报告目录也预创建
        os.makedirs(os.path.join(self.batch_audit_dir, 'audit_reports'), exist_ok=True)

    def get_report_dir(self, report_type: str) -> str:
        dir_name = self.REPORT_TYPE_DIR_MAP.get(report_type, f"report/{report_type}")
        report_dir = os.path.join(self.batch_audit_dir, dir_name)
        os.makedirs(report_dir, exist_ok=True)
        return report_dir
    
    def get_raw_report_dir(self, report_type: str, date_str: str = None) -> str:
        """返回指定日期（或最新一天）的 raw_md 目录
        
        Args:
            report_type: 报告类型
            date_str: 指定日期（YYYYMMDD），None 则自动取最新一天
        """
        base = self.ai_test_agent_dir
        if date_str:
            # 精确指定日期，直接返回
            return os.path.join(base, date_str, f"{report_type}_raw_md")
        # 找所有运行目录（格式 YYYYMMDD_HHMMSS 或旧的 YYYYMMDD），取最新一次
        if os.path.exists(base):
            day_dirs = sorted([
                d for d in os.listdir(base)
                if os.path.isdir(os.path.join(base, d)) and re.match(r'^\d{8}(_\d{6})?$', d)
            ], reverse=True)
            if day_dirs:
                latest_dir = os.path.join(base, day_dirs[0], f"{report_type}_raw_md")
                print(f"  [审查] 使用最新解读报告目录: {day_dirs[0]}/{report_type}_raw_md")
                return latest_dir
        # 兼容旧结构（无日期子目录）
        return os.path.join(base, f"{report_type}_raw_md")
    
    def get_raw_report_files(self, report_type: str, date_str: str = None) -> List[str]:
        raw_md_dir = self.get_raw_report_dir(report_type, date_str)
        if not os.path.exists(raw_md_dir):
            return []
        
        report_files = []
        for filename in os.listdir(raw_md_dir):
            if filename.endswith('.md') and filename.startswith(f"{report_type}_report_"):
                report_files.append(os.path.join(raw_md_dir, filename))
        report_files.sort()
        return report_files
    
    def extract_report_id(self, filepath: str, report_type: str) -> Optional[str]:
        filename = os.path.basename(filepath)
        
        if report_type == 'asset':
            match = re.search(r'asset_report_(\d+)\.md', filename)
        elif report_type == 'alert':
            match = re.search(r'alert_report_(\d+)\.md', filename)
        elif report_type == 'event':
            match = re.search(r'event_report_(\d+)\.md', filename)
        elif report_type == 'vuln':
            match = re.search(r'vuln_report_(\d+)\.md', filename)
        else:
            return None
        
        return match.group(1) if match else None
    
    def save_audit_report(self, audit_content: str, report_type: str, report_id: str) -> str:
        report_dir = self.get_report_dir(report_type)
        audit_filename = f"{report_id}_audit.md"
        audit_filepath = os.path.join(report_dir, audit_filename)
        
        try:
            with open(audit_filepath, 'w', encoding='utf-8') as f:
                f.write(audit_content)
            print(f"  [保存成功] {audit_filepath}")
            return audit_filepath
        except Exception as e:
            print(f"  [错误] 保存审查报告失败: {audit_filepath}, {e}")
            return None
    
    def _load_skill_spec(self, skill_name: str) -> Optional[str]:
        """加载审查技能规范文件（优先从项目目录读取）
        
        加载顺序：SKILL.md 为主规范，同目录下其他 .md 文件（interpretation/template）合并追加
        """
        project_skill_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'skills'
        )
        skill_dir = os.path.join(project_skill_dir, skill_name)
        skill_path = os.path.join(skill_dir, 'SKILL.md')
        if not os.path.exists(skill_path):
            return None

        with open(skill_path, 'r', encoding='utf-8') as f:
            spec = f.read()

        # 追加同目录下的 interpretation/template 参考文件
        for fname in sorted(os.listdir(skill_dir)):
            if fname == 'SKILL.md' or not fname.endswith('.md'):
                continue
            ref_path = os.path.join(skill_dir, fname)
            with open(ref_path, 'r', encoding='utf-8') as f:
                ref_content = f.read()
            spec += f"\n\n---\n# 附件参考：{fname}\n\n{ref_content}"

        return spec
    
    def _build_system_prompt(self, skill_spec: str) -> str:
        """构建LLM系统提示词"""
        return skill_spec
    
    def _extract_report_body(self, report_content: str) -> str:
        """提取报告正文，过滤掉开头的标题和元数据"""
        if '---' in report_content:
            parts = report_content.split('---', 1)
            return parts[1].strip()
        elif '# 资产解读报告' in report_content:
            parts = report_content.split('# 资产解读报告', 1)
            return '# 资产解读报告' + parts[1]
        elif '# 告警解读报告' in report_content:
            parts = report_content.split('# 告警解读报告', 1)
            return '# 告警解读报告' + parts[1]
        elif '# 事件解读报告' in report_content:
            parts = report_content.split('# 事件解读报告', 1)
            return '# 事件解读报告' + parts[1]
        elif '# 漏洞解读报告' in report_content:
            parts = report_content.split('# 漏洞解读报告', 1)
            return '# 漏洞解读报告' + parts[1]
        return report_content
    
    def _build_user_prompt(self, report_content: str, report_type: str) -> str:
        """构建LLM用户提示词"""
        type_names = {
            'asset': '资产',
            'alert': '告警',
            'event': '事件',
            'vuln': '漏洞'
        }
        type_name = type_names.get(report_type, '报告')
        return f"""## 待审计{type_name}解读报告
{report_content}"""
    
    def audit_single_report(self, report_file: str, report_type: str) -> Tuple[bool, str, Dict]:
        """审查单份报告（使用LLM-as-a-Judge）
        
        Args:
            report_file: 报告文件路径
            report_type: 报告类型 (alert/event/vuln)
        
        Returns:
            (success, audit_content, metadata)
        """
        report_id = self.extract_report_id(report_file, report_type)
        skill_name = self.REPORT_TYPE_SKILL_MAP.get(report_type)
        
        if not report_id or not skill_name:
            print(f"  [跳过] 无法识别报告ID或技能: {report_file}")
            return False, "", {"report_id": report_id, "error": "无法识别报告ID或技能"}
        
        print(f"\n{'='*60}")
        print(f"🔍 开始审查 {self.REPORT_TYPE_NAME_MAP[report_type]}报告: {report_id}")
        print(f"{'='*60}")
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report_content = f.read()

            # 判断是否为未生成报告（文件存在但内容为空或不含有效解读内容）
            REPORT_MARKERS = ['# 资产解读报告', '# 告警解读报告', '# 事件解读报告', '# 漏洞解读报告', 'CVE-']
            content_stripped = report_content.strip()
            if not content_stripped or not any(marker in report_content for marker in REPORT_MARKERS):
                print(f"  [不可审查] 报告 {report_id} 内容为空或未生成有效解读，跳过审查")
                return False, "", {"report_id": report_id, "error": "未生成解读报告", "not_auditable": True}

            report_content = self._extract_report_body(report_content)
        except Exception as e:
            print(f"  [错误] 读取报告失败: {e}")
            return False, "", {"report_id": report_id, "error": f"读取报告失败: {e}"}
        
        skill_spec = self._load_skill_spec(skill_name)
        if not skill_spec:
            print(f"  [错误] 无法加载审查技能规范: {skill_name}")
            return False, "", {"report_id": report_id, "error": f"无法加载审查技能规范: {skill_name}"}
        
        system_prompt = self._build_system_prompt(skill_spec)
        user_prompt = self._build_user_prompt(report_content, report_type)
        
        print(f"  [调用LLM] 正在审查报告 {report_id}...")
        audit_result = self.llm_client.call_llm(system_prompt, user_prompt, max_tokens=8192)
        
        if audit_result:
            print(f"  [审查完成] 报告 {report_id} 审查成功")
            audit_result = self._clean_audit_result(audit_result)
            audit_filepath = self.save_audit_report(audit_result, report_type, report_id)
            
            metadata = self._parse_audit_result(audit_result, report_id)
            metadata['file_path'] = audit_filepath
            
            return True, audit_result, metadata
        else:
            print(f"  [错误] LLM调用失败，无法生成审查报告")
            return False, "", {"report_id": report_id, "error": "LLM调用失败"}
    
    def _clean_audit_result(self, audit_result: str) -> str:
        """清洗 LLM 审计输出：剥离 ```markdown 包裹和前置引导语，确保解析正则能正常匹配"""
        import re as _re
        text = audit_result.strip()

        # 1. 剥离整体 ```markdown ... ``` 包裹（LLM 将整个审计报告包在代码块中的情况）
        md_wrap = _re.match(r'^```(?:markdown)?\s*\n(.*?)\n?```\s*$', text, _re.DOTALL)
        if md_wrap:
            text = md_wrap.group(1).strip()

        # 2. 如果 ## 📊 总体审计结论 之前有前置引导语，剥离它
        marker = '## 📊 总体审计结论'
        idx = text.find(marker)
        if idx > 0:
            print(f"  [清洗] 检测到前置引导语（{idx}字符），已剥离")
            text = text[idx:]

        # 3. 去掉方括号中的数字（[97] → 97），避免正则匹配失败
        #    仅对"综合得分"和评分详情表中的分值做替换，不影响其他内容
        text = _re.sub(r'\[(\d+)\s*/\s*100\]', r'\1 / 100', text)   # [97 / 100] → 97 / 100
        text = _re.sub(r'\[(\d+)\]分', r'\1分', text)                 # [14]分 → 14分
        text = _re.sub(r'\[(\d+)\]\s*分', r'\1分', text)              # [14] 分 → 14分

        return text

    def _parse_audit_result(self, audit_result: str, report_id: str) -> Dict:
        """解析审查结果，提取关键元数据"""
        metadata = {
            'report_id': report_id,
            'rating': '',
            'score': 0,
            'violation_count': 0,
            'violation_types': [],
            'summary': ''
        }
        
        try:
            # 合规评级
            rating_match = re.search(r'合规评级\*\*\s*[：:]\s*([^\n]+)', audit_result)
            if rating_match:
                metadata['rating'] = rating_match.group(1).strip()

            # 一句话总评
            summary_match = re.search(r'一句话总评\*\*\s*[：:]\s*(.+?)(?:\n|$)', audit_result)
            if summary_match:
                metadata['summary'] = summary_match.group(1).strip()
            
            # 综合得分
            score_match = re.search(r'综合得分\*\*\s*[：:]\s*(\d+)\s*/\s*100', audit_result)
            if not score_match:
                score_match = re.search(r'综合得分\*\*\s*[：:]\s*(\d+)', audit_result)
            if score_match:
                metadata['score'] = int(score_match.group(1))

            # 从评分详情表强制重算综合得分（不信任 LLM 的算术）
            # 精确定位 "## 📈 评分详情" 区块，避免匹配到报告中其他表格
            score_section = re.search(
                r'##\s*📈\s*评分详情.*?(?=\n##|\Z)',
                audit_result, re.DOTALL
            )
            score_block = score_section.group(0) if score_section else audit_result
            detail_score_rows = re.findall(
                r'\|\s*\**[^|]+?\**\s*\|\s*(\d+)\s*分?\s*\|\s*(\d+)\s*分?\s*\|',
                score_block
            )
            if detail_score_rows:
                calculated_score = sum(int(row[1]) for row in detail_score_rows)
                if 0 <= calculated_score <= 100:
                    if calculated_score != metadata['score']:
                        print(f"  [修正] 综合得分{metadata['score']}→累加值{calculated_score}（评分详情表各维度之和强制重算）")
                    metadata['score'] = calculated_score
            
            # 违规项计数 + 违规类型
            # 格式：发现 4 处违规，其中硬编码话术不一致 1 处，含有英文字段 1 处，逻辑冲突 2 处
            count_match = re.search(
                r'违规项计数\*\*\s*[：:]\s*发现\s*(\d+)\s*处违规[，,]?\s*(?:其中)?(.*?)(?:\n|$)',
                audit_result
            )
            if count_match:
                metadata['violation_count'] = int(count_match.group(1))
                detail_str = count_match.group(2).strip()
                if detail_str and metadata['violation_count'] > 0:
                    # 匹配"描述 N处"格式，只保留 N>0 的类型
                    types = re.findall(r'([^\d，,。、；]+?)\s*(\d+)\s*处', detail_str)
                    metadata['violation_types'] = [
                        t[0].strip() for t in types
                        if t[0].strip() and int(t[1]) > 0
                    ]
            else:
                # 无违规项计数行，尝试通用匹配
                count_match2 = re.search(r'(\d+)\s*处违规', audit_result)
                if count_match2:
                    metadata['violation_count'] = int(count_match2.group(1))
        
        except Exception as e:
            print(f"  [警告] 解析审查结果失败: {e}")
        
        return metadata
    
    def batch_audit(self, report_type: str, date_str: str = None) -> Dict[str, List[Dict]]:
        """批量审查指定类型的所有报告
        
        Args:
            report_type: 报告类型 (alert/event/vuln/asset)
            date_str: 指定读取哪天的解读报告（YYYYMMDD），None 则取最新一天
        
        Returns:
            审查结果统计
        """
        print(f"\n{'='*70}")
        print(f"🚀 开始批量审查 {self.REPORT_TYPE_NAME_MAP[report_type]}解读报告")
        print(f"{'='*70}")
        
        report_files = self.get_raw_report_files(report_type, date_str)
        if not report_files:
            print(f"  [警告] 未找到任何{self.REPORT_TYPE_NAME_MAP[report_type]}解读报告")
            return {
                'success': [],
                'failed': [],
                'summary': {
                    'total': 0,
                    'success_count': 0,
                    'failed_count': 0,
                    'avg_score': 0
                }
            }
        
        print(f"  [准备] 共找到 {len(report_files)} 份报告待审查")
        
        success_results = []
        failed_results = []
        not_auditable_results = []  # 未生成有效解读报告，不可审查
        
        for report_file in report_files:
            success, content, metadata = self.audit_single_report(report_file, report_type)
            if success:
                success_results.append(metadata)
            elif metadata.get('not_auditable'):
                not_auditable_results.append(metadata)
            else:
                failed_results.append(metadata)
        
        avg_score = 0
        if success_results:
            avg_score = sum(r.get('score', 0) for r in success_results) / len(success_results)
        
        summary = {
            'total': len(report_files),
            'success_count': len(success_results),
            'failed_count': len(failed_results),
            'not_auditable_count': len(not_auditable_results),
            'avg_score': round(avg_score, 2)
        }
        
        print(f"\n{'='*70}")
        print(f"📊 批量审查完成")
        print(f"{'='*70}")
        print(f"  总报告数: {summary['total']}")
        print(f"  成功审查: {summary['success_count']}")
        print(f"  审查失败: {summary['failed_count']}")
        print(f"  不可审查: {summary['not_auditable_count']}（未生成有效解读报告）")
        print(f"  平均得分: {summary['avg_score']}分")
        
        self._generate_summary_report(report_type, success_results, failed_results, not_auditable_results, summary)
        
        return {
            'success': success_results,
            'failed': failed_results,
            'not_auditable': not_auditable_results,
            'summary': summary
        }
    
    def _generate_summary_report(self, report_type: str, success_results: List[Dict],
                                  failed_results: List[Dict], not_auditable_results: List[Dict], summary: Dict) -> None:
        """生成审查总结报告"""
        report_dir = self.get_report_dir(report_type)
        summary_file = os.path.join(report_dir, f"{report_type}_audit_summary.md")
        
        report_type_name = self.REPORT_TYPE_NAME_MAP[report_type]
        
        not_auditable_count = summary.get('not_auditable_count', 0)
        content = f"""# {report_type_name}解读报告审查总结

**审查时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**审查范围**：{summary['total']}份{report_type_name}解读报告
**审查方式**：LLM-as-a-Judge（基于{self.REPORT_TYPE_SKILL_MAP[report_type]}技能规范）

---

## 📊 审查统计

| 指标 | 数值 |
|------|------|
| 总报告数 | {summary['total']}份 |
| 成功审查 | {summary['success_count']}份 |
| 审查失败 | {summary['failed_count']}份 |
| 不可审查 | {not_auditable_count}份 |
| 成功审查平均得分 | {summary['avg_score']}分 |

---

## 📈 成功审查报告详情

| {report_type_name}ID | 合规评级 | 得分 | 违规项数 | 违规项内容 | 一句话总评 |
|-------------------|----------|------|----------|-----------|-----------|
"""
        
        for result in success_results:
            # violation_types 中的 | 需转义，避免破坏 markdown 表格列
            vt_list = result.get('violation_types', [])
            violation_types_str = ('；'.join(vt_list) or '-').replace('|', '｜')
            summary_str = (result.get('summary', '') or '-').replace('|', '｜').replace('\n', ' ')
            content += f"| {result.get('report_id', '')} | {result.get('rating', '')} | {result.get('score', 0)}分 | {result.get('violation_count', 0)}处 | {violation_types_str} | {summary_str} |\n"
        
        content += "\n---\n\n"
        
        if not_auditable_results:
            content += f"""## ⚠️ 不可审查报告详情（未生成有效解读）

| {report_type_name}ID | 原因 |
|-------------------|------|
"""
            for result in not_auditable_results:
                content += f"| {result.get('report_id', '')} | {result.get('error', '未生成解读报告')} |\n"
            content += "\n---\n\n"

        if failed_results:
            content += """## ❌ 审查失败报告详情

| {report_type_name}ID | 失败原因 |
|-------------------|----------|
""".format(report_type_name=report_type_name)
            
            for result in failed_results:
                content += f"| {result.get('report_id', '')} | {result.get('error', '')} |\n"
            
            content += "\n---\n\n"
        
        content += """## 📁 审查报告文件清单

"""
        for result in success_results:
            if result.get('file_path'):
                filename = os.path.basename(result['file_path'])
                content += f"- [{filename}](file:///{result['file_path']})\n"
        
        content += f"\n---\n\n## 🎯 结论\n\n"
        if summary['success_count'] == summary['total']:
            content += f"所有{summary['total']}份{report_type_name}解读报告均审查成功，平均得分{summary['avg_score']}分。"
        elif summary['success_count'] > 0:
            content += f"共成功审查{summary['success_count']}份报告，平均得分{summary['avg_score']}分；{summary['failed_count']}份报告审查失败，请检查后重新审查。"
        else:
            content += f"所有报告审查均失败，请检查LLM配置或报告文件。"
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"  [保存] 总结报告: {summary_file}")

    def generate_comprehensive_html(self) -> str:
        """解析所有模块的审查总结md，生成综合HTML报告"""
        report_types = ['asset', 'alert', 'event', 'vuln']
        modules_data = []

        for report_type in report_types:
            report_dir = self.get_report_dir(report_type)
            # 尝试两个可能的summary文件名
            summary_file = None
            for candidate in [f"{report_type}_audit_summary.md", f"{self.REPORT_TYPE_DIR_MAP[report_type]}_audit_summary.md"]:
                candidate_path = os.path.join(report_dir, candidate)
                if os.path.exists(candidate_path):
                    summary_file = candidate_path
                    break

            if not summary_file:
                continue

            parsed = self._parse_summary_md(summary_file, report_type)
            if parsed:
                modules_data.append(parsed)

        if not modules_data:
            print("  [警告] 未找到任何审查总结文件")
            return ""

        html = self._build_comprehensive_audit_html(modules_data)
        # 日期目录下的 audit_reports
        output_dir = os.path.join(self.batch_audit_dir, "audit_reports")
        os.makedirs(output_dir, exist_ok=True)
        html_path = os.path.join(output_dir, "audit_comprehensive.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        # 根目录保留 latest 指向最新一份，方便直接访问
        latest_dir = os.path.join(self._batch_audit_root, "audit_reports")
        os.makedirs(latest_dir, exist_ok=True)
        latest_path = os.path.join(latest_dir, "audit_comprehensive.html")
        with open(latest_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"\n📄 综合审查HTML报告: {html_path}")
        return html_path

    def _parse_summary_md(self, filepath: str, report_type: str) -> Optional[Dict]:
        """解析单个审查总结md文件"""
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        type_names = {'asset': '资产解读', 'alert': '安全告警解读', 'event': '安全事件解读', 'vuln': '漏洞解读'}
        id_labels = {'asset': '资产ID', 'alert': '告警ID', 'event': '事件ID', 'vuln': '漏洞ID'}

        result = {
            'type': report_type,
            'type_name': type_names.get(report_type, report_type),
            'id_label': id_labels.get(report_type, 'ID'),
        }

        # 审查时间
        m = re.search(r'\*\*审查时间\*\*[：:]\s*(.+?)(?:\n|$)', content)
        result['audit_time'] = m.group(1).strip() if m else ''

        # 审查范围
        m = re.search(r'\*\*审查范围\*\*[：:]\s*(.+?)(?:\n|$)', content)
        result['audit_scope'] = m.group(1).strip() if m else ''

        # 审查统计表 — avg_score 保留2位小数
        for row_label, key in [('总报告数', 'total'), ('成功审查', 'success_count'), ('审查失败', 'failed_count'), ('不可审查', 'not_auditable_count'), ('成功审查平均得分', 'avg_score')]:
            m = re.search(rf'\|\s*{row_label}\s*\|\s*(.+?)\s*\|', content)
            if m:
                val = m.group(1).strip()
                if key == 'avg_score':
                    val = val.rstrip('分')
                    try:
                        result[key] = round(float(val), 2)
                    except ValueError:
                        result[key] = 0
                elif key in ['total', 'success_count', 'failed_count', 'not_auditable_count']:
                    val = val.rstrip('份')
                    try:
                        result[key] = int(val)
                    except ValueError:
                        result[key] = 0

        # 解析详情表格：精确匹配前5列（ID|评级|得分|违规数|违规内容），避免违规内容中的|破坏解析
        detail_table_match = re.search(r'## 📈 成功审查报告详情(.*?)(?:## ❌|## 📁|---\n\n## 🎯)', content, re.DOTALL)
        details = []
        if detail_table_match:
            table_text = detail_table_match.group(1)
            # 逐行解析，每行取前5个字段，第5字段取到行尾
            for line in table_text.split('\n'):
                line = line.strip()
                if not line.startswith('|'):
                    continue
                # 去掉首尾 |
                inner = line[1:]
                if inner.endswith('|'):
                    inner = inner[:-1]
                # 切前5个 |，第6段是一句话总评（可能含 |，但已转义为 ｜）
                parts = inner.split('|', 5)
                if len(parts) < 5:
                    continue
                col0 = parts[0].strip()  # ID
                col1 = parts[1].strip()  # 评级
                col2 = parts[2].strip()  # 得分
                col3 = parts[3].strip()  # 违规数
                col4 = parts[4].strip() if len(parts) > 4 else ''  # 违规内容
                col5 = parts[5].strip() if len(parts) > 5 else ''  # 一句话总评

                # 跳过表头和分隔线
                if not col0 or '---' in col0 or col0 in ('告警ID', '事件ID', '资产ID', '漏洞ID', '指标'):
                    continue
                # ID 必须是纯数字（跳过异常行）
                if not col0.isdigit():
                    continue

                try:
                    score = int(col2.rstrip('分'))
                except ValueError:
                    score = 0
                try:
                    violations = int(col3.rstrip('处'))
                except ValueError:
                    violations = 0

                details.append({
                    'id': col0,
                    'rating': col1,
                    'score': score,
                    'violations': violations,
                    'violation_types': col4 if col4 and col4 != '-' else '',
                    'summary': col5 if col5 and col5 != '-' else '',
                })
        result['details'] = details

        # 不可审查列表
        not_auditable_match = re.search(r'## ⚠️ 不可审查报告详情.*?(.*?)(?:## ❌|## 📁|---\n\n## 🎯)', content, re.DOTALL)
        not_auditable_list = []
        if not_auditable_match:
            na_rows = re.findall(r'\|\s*([^\|]+?)\s*\|\s*([^\|]+?)\s*\|', not_auditable_match.group(1))
            for row in na_rows:
                if 'ID' in row[0] or '---' in row[0] or '原因' in row[1]:
                    continue
                rid = row[0].strip()
                if rid and rid.isdigit():
                    not_auditable_list.append({'id': rid, 'reason': row[1].strip()})
        result['not_auditable_list'] = not_auditable_list

        # 失败列表
        failed_match = re.search(r'## ❌ 审查失败报告详情(.*?)(?:## 📁|---\n\n## 🎯)', content, re.DOTALL)
        failed_list = []
        if failed_match:
            failed_rows = re.findall(r'\|\s*([^\|]+?)\s*\|\s*([^\|]+?)\s*\|', failed_match.group(1))
            for row in failed_rows:
                if 'ID' in row[0] or '---' in row[0]:
                    continue
                failed_list.append({'id': row[0].strip(), 'reason': row[1].strip()})
        result['failed_list'] = failed_list

        return result

    def _build_comprehensive_audit_html(self, modules_data: List[Dict]) -> str:
        """构建综合审查HTML报告"""
        # 总体统计
        grand_total = sum(m.get('total', 0) for m in modules_data)
        grand_success = sum(m.get('success_count', 0) for m in modules_data)
        grand_failed = sum(m.get('failed_count', 0) for m in modules_data)
        grand_not_auditable = sum(m.get('not_auditable_count', 0) for m in modules_data)

        all_scores = []
        for m in modules_data:
            for d in m.get('details', []):
                all_scores.append(d['score'])
        overall_avg = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0

        def rating_class(score):
            if score >= 90: return 'perfect'
            if score >= 70: return 'good'
            if score >= 40: return 'warning'
            return 'danger'

        def rating_badge(rating_text):
            if '完全合规' in rating_text: return 'badge-perfect'
            if '局部瑕疵' in rating_text: return 'badge-good'
            if '严重违规' in rating_text: return 'badge-danger'
            return 'badge-warning'

        # 各模块卡片
        module_cards = []
        for m in modules_data:
            m_total = m.get('total', 0)
            m_success = m.get('success_count', 0)
            m_failed = m.get('failed_count', 0)
            m_not_auditable = m.get('not_auditable_count', 0)
            m_avg = m.get('avg_score', 0)
            m_avg = float(m_avg) if m_avg else 0
            rc = rating_class(m_avg)

            # 得分分布
            perfect_count = sum(1 for d in m['details'] if d['score'] >= 90)
            good_count = sum(1 for d in m['details'] if 70 <= d['score'] < 90)
            warning_count = sum(1 for d in m['details'] if 40 <= d['score'] < 70)
            danger_count = sum(1 for d in m['details'] if d['score'] < 40)

            # 详情行
            detail_rows = []
            for d in m['details']:
                vt = d.get('violation_types', '')
                vt_html = f'<div class="violation-detail">{vt}</div>' if vt and vt != '-' else ''
                summary_text = d.get('summary', '')
                summary_html = f'<div class="audit-summary">{summary_text}</div>' if summary_text else '-'
                detail_rows.append(f"""
                <tr>
                    <td class="td-id">{d['id']}</td>
                    <td><span class="{rating_badge(d['rating'])}">{d['rating']}</span></td>
                    <td class="td-score"><span class="score-{rating_class(d['score'])}">{d['score']}<span class="score-unit">分</span></span></td>
                    <td class="td-violation">{d['violations']}<span class="violation-unit">处</span></td>
                    <td class="td-violation-content">{vt_html if vt_html else '-'}</td>
                    <td class="td-summary">{summary_html}</td>
                </tr>""")

            # 不可审查行（未生成有效解读报告）
            for na in m.get('not_auditable_list', []):
                detail_rows.append(f"""
                <tr class="tr-not-auditable">
                    <td class="td-id">{na['id']}</td>
                    <td><span class="badge-not-auditable">不可审查</span></td>
                    <td class="td-score">-</td>
                    <td>-</td>
                    <td class="td-reason">未生成有效解读报告</td>
                    <td>-</td>
                </tr>""")

            # 失败行
            for f in m.get('failed_list', []):
                detail_rows.append(f"""
                <tr class="tr-failed">
                    <td class="td-id">{f['id']}</td>
                    <td><span class="badge-failed">审查失败</span></td>
                    <td class="td-score">-</td>
                    <td>-</td>
                    <td class="td-reason">{f['reason']}</td>
                    <td>-</td>
                </tr>""")

            module_cards.append(f"""
            <div class="module-card">
                <div class="module-header">
                    <h3>{m['type_name']}</h3>
                    <div class="module-stats-row">
                        <div class="stat-item">
                            <div class="stat-num">{m_total}</div>
                            <div class="stat-label">总报告</div>
                        </div>
                        <div class="stat-item success">
                            <div class="stat-num">{m_success}</div>
                            <div class="stat-label">审查成功</div>
                        </div>
                        <div class="stat-item {'danger' if m_failed > 0 else ''}">
                            <div class="stat-num">{m_failed}</div>
                            <div class="stat-label">审查失败</div>
                        </div>
                        <div class="stat-item {'not-auditable' if m_not_auditable > 0 else ''}">
                            <div class="stat-num">{m_not_auditable}</div>
                            <div class="stat-label">不可审查</div>
                        </div>
                        <div class="stat-item avg-{rc}">
                            <div class="stat-num">{m_avg}</div>
                            <div class="stat-label">平均分</div>
                        </div>
                    </div>
                    <div class="score-bar-container">
                        <div class="score-bar perfect" style="flex:{perfect_count}"><span>{perfect_count} 合规</span></div>
                        <div class="score-bar good" style="flex:{good_count}"><span>{good_count} 瑕疵</span></div>
                        <div class="score-bar warning" style="flex:{warning_count}"><span>{warning_count} 违规</span></div>
                        <div class="score-bar danger" style="flex:{danger_count}"><span>{danger_count} 重写</span></div>
                    </div>
                </div>
                <table class="detail-table">
                    <thead>
                        <tr>
                            <th>{m['id_label']}</th>
                            <th>合规评级</th>
                            <th>得分</th>
                            <th>违规数</th>
                            <th>违规项内容</th>
                            <th>一句话总评</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(detail_rows)}
                    </tbody>
                </table>
            </div>""")

        css = """
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;color:#333;line-height:1.6;padding:24px}
        .container{max-width:1200px;margin:0 auto}
        .header{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);color:#fff;border-radius:16px;padding:32px 40px;margin-bottom:24px}
        .header h1{font-size:26px;margin-bottom:8px}
        .header .sub{opacity:.75;font-size:14px}
        .summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:24px}
        .summary-card{background:#fff;border-radius:12px;padding:20px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.06)}
        .summary-card .num{font-size:32px;font-weight:700;color:#1a1a2e}
        .summary-card .num.danger{color:#e53e3e}
        .summary-card .num.success{color:#38a169}
        .summary-card .lbl{font-size:13px;color:#666;margin-top:4px}
        .module-card{background:#fff;border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
        .module-header h3{font-size:18px;color:#1a1a2e;margin-bottom:12px;padding-bottom:8px;border-bottom:2px solid #e2e8f0}
        .module-stats-row{display:flex;gap:24px;margin-bottom:12px}
        .stat-item{text-align:center}
        .stat-item .stat-num{font-size:22px;font-weight:700;color:#4a5568}
        .stat-item.success .stat-num{color:#38a169}
        .stat-item.danger .stat-num{color:#e53e3e}
        .stat-item.avg-perfect .stat-num{color:#38a169}
        .stat-item.avg-good .stat-num{color:#d69e2e}
        .stat-item.avg-warning .stat-num{color:#dd6b20}
        .stat-item.avg-danger .stat-num{color:#e53e3e}
        .stat-label{font-size:12px;color:#999}
        .score-bar-container{display:flex;gap:4px;height:24px;border-radius:6px;overflow:hidden;margin-top:8px}
        .score-bar{display:flex;align-items:center;justify-content:center;font-size:11px;color:#fff;min-width:40px}
        .score-bar.perfect{background:#38a169}
        .score-bar.good{background:#d69e2e}
        .score-bar.warning{background:#dd6b20}
        .score-bar.danger{background:#e53e3e}
        .detail-table{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px}
        .detail-table th{background:#f7fafc;padding:10px 12px;text-align:left;color:#666;font-weight:600;border-bottom:2px solid #e2e8f0}
        .detail-table td{padding:10px 12px;border-bottom:1px solid #f0f0f0}
        .td-id{font-family:'SF Mono',monospace;color:#4a5568;font-size:12px}
        .td-score{font-weight:700;text-align:center}
        .td-violation{text-align:center;color:#e53e3e;font-weight:600}
        .violation-detail{font-size:11px;color:#742a2a;font-weight:400;margin-top:4px;text-align:left;line-height:1.5;white-space:normal}
        .td-violation-content{text-align:left;white-space:normal}
        .td-summary{font-size:11px;color:#4a5568;text-align:left;line-height:1.5;max-width:300px;white-space:normal}
        .audit-summary{color:#4a5568;font-weight:400}
        .td-reason{color:#999;font-size:12px}
        .tr-failed{background:#fff5f5}
        .score-perfect{color:#38a169;font-size:16px}
        .score-good{color:#d69e2e;font-size:16px}
        .score-warning{color:#dd6b20;font-size:16px}
        .score-danger{color:#e53e3e;font-size:16px}
        .score-unit{font-size:12px;font-weight:400;margin-left:1px}
        .violation-unit{font-size:12px;font-weight:400;margin-left:1px;color:#e53e3e}
        .badge-perfect{display:inline-block;background:#c6f6d5;color:#22543d;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
        .badge-good{display:inline-block;background:#fefcbf;color:#975a16;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
        .badge-warning{display:inline-block;background:#feebc8;color:#7b341e;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
        .badge-danger{display:inline-block;background:#fed7d7;color:#742a2a;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
        .badge-failed{display:inline-block;background:#e2e8f0;color:#718096;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
        .badge-not-auditable{display:inline-block;background:#fef3c7;color:#92400e;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
        .tr-not-auditable{background:#fffbeb}
        .stat-item.not-auditable .stat-num{color:#d97706}
        .summary-card .num.not-auditable{color:#d97706}
        .footer{text-align:center;color:#999;font-size:12px;padding:20px}
        """

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>AI解读审查综合报告</title>
    <style>{css}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 AI解读审查综合报告</h1>
            <div class="sub">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 审查方式: LLM-as-a-Judge</div>
        </div>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="num">{grand_total}</div>
                <div class="lbl">审查报告总数</div>
            </div>
            <div class="summary-card">
                <div class="num success">{grand_success}</div>
                <div class="lbl">成功审查</div>
            </div>
            <div class="summary-card">
                <div class="num danger">{grand_failed}</div>
                <div class="lbl">审查失败</div>
            </div>
            <div class="summary-card">
                <div class="num not-auditable">{grand_not_auditable}</div>
                <div class="lbl">不可审查</div>
            </div>
            <div class="summary-card">
                <div class="num">{overall_avg}</div>
                <div class="lbl">整体平均分</div>
            </div>
        </div>
        {''.join(module_cards)}
        <div class="footer">AIXDR 解读模块 · 自动审查报告 · {datetime.now().strftime('%Y')}</div>
    </div>
</body>
</html>"""