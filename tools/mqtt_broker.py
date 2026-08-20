"""Local MQTT broker for CADS demo runs."""

import asyncio

from amqtt.broker import Broker


CONFIG = {
    "listeners": {
        "default": {
            "type": "tcp",
            "bind": "127.0.0.1:1883",
        }
    },
    "sys_interval": 10,
    "topic-check": {"enabled": False},
}


async def main():
    broker = Broker(CONFIG)
    await broker.start()
    print("[MQTT] Broker listening on 127.0.0.1:1883")
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await broker.shutdown()


if __name__ == "__main__":
    asyncio.run(main())