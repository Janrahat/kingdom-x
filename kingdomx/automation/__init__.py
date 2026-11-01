"""Automation: scheduled tasks and safe command execution.

Two parts:

* :mod:`kingdomx.automation.scheduler` — persisted task definitions with
  interval scheduling, run history, and no daemon (the operator's `kingdomx run-due`
  call decides when to fire).
* :mod:`kingdomx.automation.executor` — runs a *named* action from an allow-list.
  Arbitrary shell strings are rejected by design.
"""

from kingdomx.automation.scheduler import (
    ScheduledTask,
    create_task,
    delete_task,
    due_tasks,
    list_tasks,
    run_due,
    record_run,
    ALLOWED_ACTIONS,
)
from kingdomx.automation.executor import run_action, ActionError

__all__ = [
    "ScheduledTask",
    "create_task",
    "delete_task",
    "due_tasks",
    "list_tasks",
    "run_due",
    "record_run",
    "ALLOWED_ACTIONS",
    "run_action",
    "ActionError",
]
