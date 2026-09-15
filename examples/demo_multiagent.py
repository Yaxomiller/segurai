"""The scenario the whole product exists for.

Sarah asks for a cleanup. Her request passes through an assistant to a CRM
agent, which decides to delete 400 records. Every existing tool would record
"a service account performed a delete". This records who asked, what they
asked for, and that the delete exceeded it.

Run:  python examples/demo_multiagent.py
"""

import warrant
from warrant import Scope


@warrant.agent("assistant")
def assistant(instruction: str) -> str:
    """Top-level assistant. Looks around, then delegates the actual work."""
    warrant.act("read", "crm.opportunities", scale=1, note="surveying the data")
    return crm_agent(instruction)


@warrant.agent(
    "crm_agent",
    # The assistant hands the CRM agent a deliberately narrower warrant:
    # it may touch opportunities only, and it may not touch accounts.
    scope=Scope.of(
        operations=["read", "delete"],
        targets=["crm.opportunities"],
        max_scale=50,
    ),
)
def crm_agent(instruction: str) -> str:
    """Does the cleanup. Finds 412 candidates, decides to delete 400."""
    warrant.act("read", "crm.opportunities", scale=412, note="scanning for stale rows")

    # Here is the moment. The human said "clean up old records". The agent has
    # decided that means deleting 400 of them. The permission system of every
    # existing tool says yes - it holds a valid delete credential.
    result = warrant.act(
        "delete",
        "crm.opportunities",
        scale=400,
        irreversible=True,
        note="deleting rows with no activity in 180d",
    )
    return "deleted" if result.allowed else f"blocked: {result.violation}"


def main() -> None:
    warrant.configure(store=":memory:", mode=warrant.Mode.OBSERVE)

    # What Sarah is understood to have authorized. In M1 this is produced from
    # her sentence by the intent compiler; here it is written out by hand.
    granted = Scope.of(
        operations=["read", "update", "delete"],
        targets=["crm.*"],
        max_scale=50,
        irreversible_allowed=False,
        constraints=["only records with no recent activity",
                     "must not affect active customers"],
    )

    with warrant.session(
        principal="sarah@company.com",
        request="clean up our old sales records",
        scope=granted,
    ) as s:
        assistant("clean up our old sales records")

        print(warrant.render(s.session_id))
        print()

        problems = warrant.verify_session(s.session_id)
        if problems:
            print("Chain verification FAILED:")
            for p in problems:
                print(f"  - {p}")
        else:
            print("Chain verification: every hop signed, linked and attenuated.")

        used = warrant.summary(s.session_id)["exercised"]
        print()
        print("Granted vs exercised (the seed of the scope-creep report):")
        print(f"  granted operations : {sorted(granted.operations)}")
        print(f"  exercised          : {used['operations']}")
        unused = sorted(set(granted.operations) - set(used["operations"]))
        print(f"  never used         : {unused}")


if __name__ == "__main__":
    main()
