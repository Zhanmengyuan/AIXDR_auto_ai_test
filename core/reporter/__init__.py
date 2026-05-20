"""
报告生成层
生成评测报告
"""
from .report_generator import ReportGenerator
from .html_report_generator import HTMLReportGenerator

__all__ = ["ReportGenerator", "HTMLReportGenerator"]
