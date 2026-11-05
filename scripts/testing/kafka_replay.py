import argparse
import json
import time
import uuid

from kafka import KafkaConsumer, KafkaProducer, TopicPartition


TARGETS = {
    "ai-result-topic.DLT": "ai-result-topic",
    "log-topic.DLT": "log-topic",
    # Existing failures before DLT support was introduced.
    "ai-result-topic": "ai-result-topic",
}


def extract_log_id(record):
    try:
        value = json.loads(record.value)
        log_id = value.get("log_id") if isinstance(value, dict) else None
        return log_id if type(log_id) is int else None
    except (ValueError, TypeError, UnicodeError):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["list", "replay"])
    parser.add_argument("--topic", required=True, choices=TARGETS)
    parser.add_argument("--log-id", type=int)
    parser.add_argument("--partition", type=int)
    parser.add_argument("--offset", type=int)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()

    if not 1 <= args.limit <= 100:
        parser.error("limit must be between 1 and 100")

    if args.mode == "replay":
        if (
            not args.confirm
            or args.partition is None
            or args.partition < 0
            or args.offset is None
            or args.offset < 0
        ):
            parser.error("replay requires partition, offset and confirm")

    consumer = KafkaConsumer(
        bootstrap_servers="kafka:29092",
        group_id=None,
        enable_auto_commit=False,
        request_timeout_ms=15000,
        session_timeout_ms=10000,
        api_version_auto_timeout_ms=5000,
    )

    selected = None
    emitted = 0

    try:
        partitions = consumer.partitions_for_topic(args.topic)
        if not partitions:
            raise RuntimeError("TOPIC_NOT_FOUND")

        if args.mode == "replay":
            if args.partition not in partitions:
                raise RuntimeError("PARTITION_NOT_FOUND")
            assigned = [TopicPartition(args.topic, args.partition)]
        else:
            assigned = [
                TopicPartition(args.topic, p)
                for p in sorted(partitions)
            ]

        consumer.assign(assigned)

        beginnings = consumer.beginning_offsets(assigned)
        ends = consumer.end_offsets(assigned)

        for tp in assigned:
            offset = (
                args.offset
                if args.mode == "replay"
                else beginnings[tp]
            )

            if args.mode == "replay":
                if not beginnings[tp] <= offset < ends[tp]:
                    raise RuntimeError("OFFSET_NOT_AVAILABLE")

            consumer.seek(tp, offset)

        deadline = time.monotonic() + 20

        while time.monotonic() < deadline:
            batches = consumer.poll(
                timeout_ms=500,
                max_records=500,
            )

            for tp, records in batches.items():
                for record in records:
                    if record.offset >= ends[tp]:
                        continue

                    if args.mode == "replay":
                        if record.offset == args.offset:
                            selected = record
                            break
                        if record.offset > args.offset:
                            raise RuntimeError("OFFSET_NOT_AVAILABLE")
                    else:
                        log_id = extract_log_id(record)

                        if (
                            args.log_id is not None
                            and log_id != args.log_id
                        ):
                            continue

                        print(json.dumps({
                            "topic": record.topic,
                            "partition": record.partition,
                            "offset": record.offset,
                            "logId": log_id,
                            "valueBytes": len(record.value or b""),
                        }), flush=True)

                        emitted += 1

                        if emitted >= args.limit:
                            print("SCAN_LIMIT")
                            return

                if selected is not None:
                    break

            if selected is not None:
                break

            if all(
                consumer.position(tp) >= ends[tp]
                for tp in assigned
            ):
                break
        else:
            raise RuntimeError("SCAN_TIMEOUT")

        if args.mode == "list":
            print("SCAN_COMPLETE")
            return

        if selected is None or selected.value is None:
            raise RuntimeError("REPLAY_RECORD_NOT_AVAILABLE")

    finally:
        consumer.close()

    replay_id = str(uuid.uuid4())

    producer = KafkaProducer(
        bootstrap_servers="kafka:29092",
        acks="all",
        retries=0,
        max_block_ms=5000,
        request_timeout_ms=10000,
    )

    try:
        result = producer.send(
            TARGETS[args.topic],
            key=selected.key,
            value=selected.value,
            headers=[
                ("dg-replay-id", replay_id.encode()),
                ("dg-source-topic", args.topic.encode()),
                ("dg-source-partition", str(args.partition).encode()),
                ("dg-source-offset", str(args.offset).encode()),
            ],
        ).get(timeout=20)

        print(json.dumps({
            "event": "REPLAY_ACK",
            "replayId": replay_id,
            "topic": result.topic,
            "partition": result.partition,
            "offset": result.offset,
        }))

    finally:
        producer.close(timeout=5)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(
            "FAILED: " + type(error).__name__
        )