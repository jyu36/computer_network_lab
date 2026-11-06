"""Reproducible host-pair selection for full and sampled development runs."""

import random


def select_host_pairs(host_names, roles, maximum_pairs=0, seed=0):
    """Select directed pairs, preserving the configured actors in both directions.

    Zero selects every pair. Sampling uses pair indices to avoid constructing
    a quadratic list for a large inventory.
    """
    count = len(host_names)
    total = count * (count - 1)
    if not maximum_pairs or maximum_pairs >= total:
        return [
            (source, destination)
            for source in host_names
            for destination in host_names
            if source != destination
        ]
    selected = [(roles["source"], roles["destination"])]
    if maximum_pairs > 1:
        selected.append((roles["destination"], roles["source"]))
    random_source = random.Random(seed)
    seen = set(selected)
    while len(selected) < maximum_pairs:
        source_index, destination_index = divmod(
            random_source.randrange(total), count - 1
        )
        if destination_index >= source_index:
            destination_index += 1
        pair = (host_names[source_index], host_names[destination_index])
        if pair not in seen:
            seen.add(pair)
            selected.append(pair)
    return selected
