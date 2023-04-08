"""This module implements basic symbolic execution search strategies."""
from random import randrange
from typing import List

from mythril.laser.ethereum.state.global_state import GlobalState
from . import BasicSearchStrategy
from random import choices


class DepthFirstSearchStrategy(BasicSearchStrategy):
    """Implements a depth first search strategy I.E.

    Follow one path to a leaf, and then continue to the next one
    """

    def get_strategic_global_state(self) -> GlobalState:
        """

        :return:
        """
        return self.work_list.pop()


class BreadthFirstSearchStrategy(BasicSearchStrategy):
    """Implements a breadth first search strategy I.E.

    Execute all states of a "level" before continuing
    """

    def get_strategic_global_state(self) -> GlobalState:
        """

        :return:
        """
        return self.work_list.pop(0)


class ReturnRandomNaivelyStrategy(BasicSearchStrategy):
    """chooses a random state from the worklist with equal likelihood."""

    def get_strategic_global_state(self) -> GlobalState:
        """

        :return:
        """
        if len(self.work_list) > 0:
            return self.work_list.pop(randrange(len(self.work_list)))
        else:
            raise IndexError


class ReturnWeightedRandomStrategy(BasicSearchStrategy):
    """chooses a random state from the worklist with likelihood based on
    inverse proportion to depth."""

    def get_strategic_global_state(self) -> GlobalState:
        """

        :return:
        """
        probability_distribution = [
            1 / (global_state.mstate.depth + 1) for global_state in self.work_list
        ]
        return self.work_list.pop(
            choices(range(len(self.work_list)), probability_distribution)[0]
        )
