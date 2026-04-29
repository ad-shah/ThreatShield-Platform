"""
Base class for all OSINT feed connectors.
Every feed must implement the fetch() method.
"""

from abc import ABC, abstractmethod
from typing import List


class BaseFeed(ABC):
    """
    Abstract base for threat intelligence feeds.

    Each feed must:
      - Set self.name (string identifier)
      - Implement fetch() -> list of raw dicts
      - Each dict must contain at minimum: 'indicator' key
    """

    name: str = "base"

    @abstractmethod
    def fetch(self) -> List[dict]:
        """
        Pull indicators from the feed source.
        Returns a list of raw dicts.
        """
        raise NotImplementedError

    def __repr__(self):
        return f"<Feed: {self.name}>"
