"""
Al-Ahsa Smart Bus — Utility functions.

Ported from scratch/smart-bus/smart-bus.cc:
  DistanceToRoute() — lines 270-292
"""

import math
import time
from datetime import datetime, timezone
from typing import List, Tuple

# Type aliases matching routes.py
Station = Tuple[float, float]
Route = List[Station]


def distance_to_route(pos_x: float, pos_y: float, route: Route) -> float:
    """
    Compute shortest distance from a point to any segment of a route.

    Ported from DistanceToRoute() — smart-bus.cc lines 270-292.

    Parameters
    ----------
    pos_x : float
        X coordinate of the point (meters).
    pos_y : float
        Y coordinate of the point (meters).
    route : Route
        List of (x, y) station tuples defining the route polyline.

    Returns
    -------
    float
        Minimum Euclidean distance from the point to the nearest
        route segment, in meters.
    """
    min_dist = 1e9

    for i in range(len(route) - 1):
        ax, ay = route[i]
        bx, by = route[i + 1]

        dx = bx - ax
        dy = by - ay
        len_sq = dx * dx + dy * dy

        t = 0.0
        if len_sq > 0:
            t = ((pos_x - ax) * dx + (pos_y - ay) * dy) / len_sq
            t = max(0.0, min(1.0, t))

        closest_x = ax + t * dx
        closest_y = ay + t * dy

        dist = math.sqrt(
            (pos_x - closest_x) ** 2 + (pos_y - closest_y) ** 2
        )
        if dist < min_dist:
            min_dist = dist

    return min_dist


def euclidean_distance(x1: float, y1: float, x2: float, y2: float) -> float:
    """Euclidean distance between two 2-D points."""
    return math.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2)


def timestamp_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def timestamp_epoch() -> float:
    """Return current time as a Unix epoch float (seconds)."""
    return time.time()
