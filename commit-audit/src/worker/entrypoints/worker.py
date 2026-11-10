import asyncio

import mistralai.workflows as workflows


def main() -> None:
    workflow_classes = workflows.discover_all_workflows_in_package("worker.workflows")
    asyncio.run(workflows.run_worker(workflow_classes))


if __name__ == "__main__":
    main()
