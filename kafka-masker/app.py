"""
Kafka masking service.

Consumes raw.customer.events, applies OPA-governed masking per role,
publishes to masked.customer.<role> topic.

Message headers:
  X-Role        (required) — role of the downstream consumer
  X-Customer-Id (optional, fallback to record["customer_id"])

Dead-letter queue: dlq.masking.errors — messages that fail OPA or JSON parsing.
"""
import json
import os
import sys
import time
import logging

from confluent_kafka import Consumer, Producer, KafkaError, KafkaException
from masking_sdk.masking import apply_masking
from masking_sdk.opa_client import get_masked_fields

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("kafka-masker")

BROKER       = os.getenv("KAFKA_BROKER",   "redpanda:9092")
RAW_TOPIC    = os.getenv("RAW_TOPIC",      "raw.customer.events")
DLQ_TOPIC    = os.getenv("DLQ_TOPIC",      "dlq.masking.errors")
GROUP_ID     = os.getenv("CONSUMER_GROUP", "masking-group")
DEFAULT_ROLE = os.getenv("DEFAULT_ROLE",   "agent")


def _headers_dict(msg) -> dict:
    return {k: v.decode("utf-8", errors="replace") for k, v in (msg.headers() or [])}


def _dlq(producer: Producer, original_value: bytes, error: str, headers: dict):
    dlq_headers = list(headers.items()) + [("masking-error", error.encode())]
    producer.produce(DLQ_TOPIC, value=original_value, headers=dlq_headers)
    producer.poll(0)
    log.warning("DLQ: %s", error)


def _wait_for_broker(broker: str, retries: int = 10):
    """Probe broker connectivity and ensure required topics exist."""
    from confluent_kafka.admin import AdminClient, NewTopic
    for attempt in range(retries):
        try:
            ac = AdminClient({"bootstrap.servers": broker,
                              "socket.timeout.ms": 3000})
            ac.list_topics(timeout=3)
            log.info("Broker %s reachable", broker)
            # Ensure raw input and DLQ topics exist (idempotent)
            for topic in (RAW_TOPIC, DLQ_TOPIC):
                fs = ac.create_topics([NewTopic(topic, num_partitions=1,
                                                replication_factor=1)])
                err = fs[topic].exception()
                if err and "already exists" not in str(err).lower() \
                   and "topic already exists" not in str(err).lower():
                    log.warning("create_topic %s: %s", topic, err)
                else:
                    log.info("Topic ready: %s", topic)
            return
        except Exception as exc:
            wait = 2 ** attempt
            log.info("Broker not ready (%s), retry in %ds [%d/%d]",
                     exc, wait, attempt + 1, retries)
            time.sleep(wait)
    log.error("Cannot reach broker %s after %d attempts — exiting", broker, retries)
    sys.exit(1)


def main():
    _wait_for_broker(BROKER)

    consumer = Consumer({
        "bootstrap.servers":  BROKER,
        "group.id":           GROUP_ID,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": True,
    })
    producer = Producer({"bootstrap.servers": BROKER})

    consumer.subscribe([RAW_TOPIC])
    log.info("Subscribed to %s — publishing to masked.customer.<role>", RAW_TOPIC)

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                code = msg.error().code()
                if code in (KafkaError._PARTITION_EOF,
                            KafkaError.UNKNOWN_TOPIC_OR_PART):
                    continue
                raise KafkaException(msg.error())

            raw_bytes = msg.value()
            headers   = _headers_dict(msg)

            try:
                record = json.loads(raw_bytes)
            except json.JSONDecodeError as exc:
                _dlq(producer, raw_bytes, f"json_decode: {exc}", headers)
                continue

            role        = headers.get("X-Role", DEFAULT_ROLE)
            customer_id = headers.get("X-Customer-Id",
                                      str(record.get("customer_id", "")))

            try:
                masked_fields = get_masked_fields(
                    role, customer_id, path="/api/stream"
                )
            except PermissionError as exc:
                _dlq(producer, raw_bytes, f"opa_denied: {exc}", headers)
                continue
            except Exception as exc:
                _dlq(producer, raw_bytes, f"opa_error: {exc}", headers)
                continue

            masked  = apply_masking(record, masked_fields)
            out_top = f"masked.customer.{role}"

            producer.produce(
                out_top,
                value=json.dumps(masked).encode(),
                headers=[(k, v.encode()) for k, v in headers.items()],
            )
            producer.poll(0)
            log.info("Masked %d field(s) for role=%s → %s",
                     len(masked_fields), role, out_top)

    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        consumer.close()
        producer.flush()


if __name__ == "__main__":
    main()
