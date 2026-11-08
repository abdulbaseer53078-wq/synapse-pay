"""`GET /health/region`, probed by the global load balancer (infra/region-failover/main.tf).

Public and unauthenticated, because Route 53's checkers can't present credentials, so it says only UP or DOWN:
nothing about which component failed.
"""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(include_in_schema=False)


@router.get("/health/live")
def live() -> JSONResponse:
    """For the load balancer's target health check: the process is serving. Deliberately not /health/region,
    which is DOWN in an unpromoted standby region by design; ECS would kill and replace those tasks forever."""
    return JSONResponse({"status": "UP"}, headers={"Cache-Control": "no-store"})


@router.get("/health/region")
def region_health(request: Request) -> JSONResponse:
    up = request.app.state.region_health.is_up()
    return JSONResponse({"status": "UP" if up else "DOWN"}, status_code=200 if up else 503,
                        headers={"Cache-Control": "no-store"})
