from collections import Counter
from typing import Dict, Iterable, Optional


def threshold_for(total_nodes: int) -> int:
    return (2 * total_nodes) // 3 + 1


def resolve_commit(votes: Iterable[Dict[str, str]], total_nodes: int) -> Optional[str]:
    counter = Counter((vote["winner"], vote["digest"]) for vote in votes)
    required = threshold_for(total_nodes)
    for key, count in counter.items():
        if count >= required:
            winner = key[0]
            return winner
    return None
