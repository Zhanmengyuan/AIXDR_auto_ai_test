"""
AIXDR智能体自动化评测框架
==========================

模块说明：
- extractors: 数据提取层（AI输出 → 结构化数据）
- api_clients: API客户端层（XDR业务接口）
- calculators: 指标计算层（AI vs API → 指标得分）
- reporter: 报告生成层

资产解读模块评测指标：
1. 风险等级准确率（多分类）  - 20分
2. 资产关键字段完整率      - 10分
3. 漏洞列表准确率          - 15分
4. 关联告警/事件准确率     - 5分
5. 格式合规率              - 5分
6. 稳定性（重复执行）      - 5分
7. 首包响应时间            - 5分
8. 平均响应时间            - 5分
9. 整体内容正确性         - 20分
"""

from .config_loader import ConfigLoader

__version__ = "1.0.0"
__all__ = ["ConfigLoader"]
