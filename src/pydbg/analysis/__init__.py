"""Analysis workbench -- unified facade for PE analysis, interception, and resource extraction."""

from .workbench import AnalysisWorkbench
from .game_analyzer import GameAnalyzer

__all__ = ["AnalysisWorkbench", "GameAnalyzer"]
