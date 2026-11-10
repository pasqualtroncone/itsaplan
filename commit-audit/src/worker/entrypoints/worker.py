import asyncio

import mistralai.workflows as workflows
from mistralai.client import Mistral


def main() -> None:
    client = Mistral()
    workflow_classes = workflows.discover_all_workflows_in_package("worker.workflows")
    asyncio.run(client.run_worker(workflow_classes))


if __name__ == "__main__":
    main()
