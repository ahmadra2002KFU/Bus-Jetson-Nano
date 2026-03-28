"""
Al-Ahsa Smart Bus — Route definitions ported from ns-3 simulation.

Source: scratch/smart-bus/smart-bus.cc
  CreateRoutes()          — lines 184-252
  GetBusRouteAssignment() — lines 258-265

Each route is a list of (x, y) station coordinates in meters.
The coordinate system matches the ns-3 simulation grid (meters, origin at 0,0).
"""

from typing import List, Tuple

# Type alias for a station coordinate (x_meters, y_meters)
Station = Tuple[float, float]
Route = List[Station]


def create_routes() -> List[Route]:
    """
    Return all 10 Al-Ahsa bus routes.

    Ported from CreateRoutes() — smart-bus.cc lines 184-252.
    Each route is a list of (x, y) tuples representing station positions.
    """
    routes: List[Route] = [None] * 10  # type: ignore[list-item]

    # Route 0 — North-South corridor along x=7500 (line 189-194)
    routes[0] = [
        (7500.0, 1000.0),
        (7500.0, 3000.0),
        (7500.0, 5000.0),
        (7500.0, 7000.0),
        (7500.0, 9000.0),
        (7500.0, 11000.0),
        (7500.0, 13000.0),
        (7500.0, 15000.0),
        (7500.0, 17000.0),
        (7500.0, 19000.0),
    ]

    # Route 1 — East-West corridor along y=10000 (lines 196-200)
    routes[1] = [
        (1000.0, 10000.0),
        (3000.0, 10000.0),
        (5000.0, 10000.0),
        (7000.0, 10000.0),
        (9000.0, 10000.0),
        (11000.0, 10000.0),
        (13000.0, 10000.0),
        (15000.0, 10000.0),
    ]

    # Route 2 — SW-to-NE diagonal (lines 202-206)
    routes[2] = [
        (1000.0, 1000.0),
        (3000.0, 3000.0),
        (5000.0, 5000.0),
        (7000.0, 7000.0),
        (9000.0, 9000.0),
        (11000.0, 11000.0),
        (13000.0, 13000.0),
    ]

    # Route 3 — NE-to-SW diagonal (lines 208-213)
    routes[3] = [
        (14000.0, 1000.0),
        (12000.0, 3000.0),
        (10000.0, 5000.0),
        (8000.0, 7000.0),
        (6000.0, 9000.0),
        (4000.0, 11000.0),
        (2000.0, 13000.0),
    ]

    # Route 4 — Southern zigzag loop (lines 214-219)
    routes[4] = [
        (3000.0, 2000.0),
        (5000.0, 1000.0),
        (7000.0, 2000.0),
        (9000.0, 1000.0),
        (11000.0, 2000.0),
        (13000.0, 1000.0),
        (11000.0, 3000.0),
        (9000.0, 4000.0),
        (7000.0, 3000.0),
        (5000.0, 4000.0),
        (3000.0, 3000.0),
    ]

    # Route 5 — Northern zigzag loop (lines 221-226)
    routes[5] = [
        (3000.0, 17000.0),
        (5000.0, 18000.0),
        (7000.0, 17000.0),
        (9000.0, 18000.0),
        (11000.0, 17000.0),
        (13000.0, 18000.0),
        (11000.0, 19000.0),
        (9000.0, 19000.0),
        (7000.0, 19000.0),
        (5000.0, 19000.0),
    ]

    # Route 6 — Central octagonal loop (lines 228-233)
    routes[6] = [
        (5000.0, 7000.0),
        (7000.0, 5000.0),
        (10000.0, 7000.0),
        (12000.0, 10000.0),
        (10000.0, 13000.0),
        (7000.0, 15000.0),
        (5000.0, 13000.0),
        (3000.0, 10000.0),
    ]

    # Route 7 — Eastern zigzag (lines 234-238)
    routes[7] = [
        (13000.0, 2000.0),
        (14000.0, 4000.0),
        (13000.0, 6000.0),
        (14000.0, 8000.0),
        (13000.0, 10000.0),
        (14000.0, 12000.0),
        (13000.0, 14000.0),
        (14000.0, 16000.0),
    ]

    # Route 8 — Western zigzag (lines 240-244)
    routes[8] = [
        (2000.0, 2000.0),
        (1000.0, 4000.0),
        (2000.0, 6000.0),
        (1000.0, 8000.0),
        (2000.0, 10000.0),
        (1000.0, 12000.0),
        (2000.0, 14000.0),
        (1000.0, 16000.0),
    ]

    # Route 9 — Long SW-to-NE express diagonal (lines 246-249)
    routes[9] = [
        (1000.0, 1000.0),
        (5000.0, 5000.0),
        (7500.0, 10000.0),
        (10000.0, 15000.0),
        (14000.0, 19000.0),
    ]

    return routes


def get_bus_route_assignment() -> List[int]:
    """
    Return the route index for each of the 41 buses.

    Ported from GetBusRouteAssignment() — smart-bus.cc lines 258-265.
    4 buses per route (routes 0-8), 5 buses on route 9.
    Index into the list = bus_id, value = route_index.
    """
    return [
        0, 0, 0, 0,   # buses 0-3   -> route 0
        1, 1, 1, 1,   # buses 4-7   -> route 1
        2, 2, 2, 2,   # buses 8-11  -> route 2
        3, 3, 3, 3,   # buses 12-15 -> route 3
        4, 4, 4, 4,   # buses 16-19 -> route 4
        5, 5, 5, 5,   # buses 20-23 -> route 5
        6, 6, 6, 6,   # buses 24-27 -> route 6
        7, 7, 7, 7,   # buses 28-31 -> route 7
        8, 8, 8, 8,   # buses 32-35 -> route 8
        9, 9, 9, 9, 9 # buses 36-40 -> route 9
    ]


def get_route_for_bus(bus_id: int) -> int:
    """Return the route index assigned to a given bus_id."""
    assignment = get_bus_route_assignment()
    if bus_id < 0 or bus_id >= len(assignment):
        raise ValueError(
            f"bus_id {bus_id} out of range [0, {len(assignment) - 1}]"
        )
    return assignment[bus_id]
