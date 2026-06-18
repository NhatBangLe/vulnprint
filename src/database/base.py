from typing import Any
from abc import ABC, abstractmethod


Connection = Any


class DatabaseManager(ABC):
    """
    Interface for managing database connections and initialization.
    """

    @abstractmethod
    def initialize_schema(self) -> None:
        """
        Initializes the database schema.
        """
        pass

    @abstractmethod
    def get_connection(self) -> Connection:
        """
        Returns a new database connection.
        """
        pass
