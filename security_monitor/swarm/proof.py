import hashlib
import json
from typing import Any, Dict, List

from security_monitor.swarm.messages import EventRecord


def _event_digest(record: Dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_hash_chain(events: List[EventRecord]) -> List[Dict[str, Any]]:
    chain: List[Dict[str, Any]] = []
    previous = "GENESIS"
    for event in events:
        event_dict = event.to_dict()
        digest = _event_digest(event_dict)
        chain_hash = hashlib.sha256(f"{previous}:{digest}".encode("utf-8")).hexdigest()
        chain_item = {
            "event": event_dict,
            "event_digest": digest,
            "prev_hash": previous,
            "chain_hash": chain_hash,
        }
        chain.append(chain_item)
        previous = chain_hash
    return chain


def _build_anchor_payload(final_chain_hash: str, event_count: int, signatures: Dict[str, str]) -> Dict[str, Any]:
    signer_ids = sorted(str(signer_id) for signer_id in signatures.keys())
    signer_digest = hashlib.sha256("|".join(signer_ids).encode("utf-8")).hexdigest()
    return {
        "final_chain_hash": final_chain_hash,
        "event_count": int(event_count),
        "signer_digest": signer_digest,
    }


def _anchor_id_from_payload(anchor_payload: Dict[str, Any]) -> str:
    payload_json = json.dumps(anchor_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def build_proof(events: List[EventRecord], signatures: Dict[str, str]) -> Dict[str, Any]:
    chain = build_hash_chain(events)
    final_hash = chain[-1]["chain_hash"] if chain else "GENESIS"
    anchor_payload = _build_anchor_payload(final_chain_hash=final_hash, event_count=len(events), signatures=signatures)
    anchor_id = _anchor_id_from_payload(anchor_payload)
    return {
        "event_count": len(events),
        "final_chain_hash": final_hash,
        "chain": chain,
        "multisig_summary": signatures,
        "anchor": {
            "anchor_id": anchor_id,
            "anchor_payload": anchor_payload,
        },
    }


def verify_proof_document(proof: Dict[str, Any]) -> Dict[str, bool]:
    chain = list(proof.get("chain", []))
    reconstructed_chain_hash = "GENESIS"
    chain_integrity_ok = True
    previous = "GENESIS"
    for chain_item in chain:
        event = dict(chain_item.get("event", {}))
        event_digest = str(chain_item.get("event_digest", ""))
        expected_event_digest = _event_digest(event)
        if expected_event_digest != event_digest:
            chain_integrity_ok = False
            break
        prev_hash = str(chain_item.get("prev_hash", ""))
        if prev_hash != previous:
            chain_integrity_ok = False
            break
        expected_chain_hash = hashlib.sha256(f"{previous}:{event_digest}".encode("utf-8")).hexdigest()
        chain_hash = str(chain_item.get("chain_hash", ""))
        if chain_hash != expected_chain_hash:
            chain_integrity_ok = False
            break
        previous = chain_hash
        reconstructed_chain_hash = chain_hash
    if not chain:
        reconstructed_chain_hash = "GENESIS"
    final_chain_hash_ok = reconstructed_chain_hash == str(proof.get("final_chain_hash", ""))
    event_count_ok = int(proof.get("event_count", -1)) == len(chain)
    signatures = dict(proof.get("multisig_summary", {}))
    anchor = dict(proof.get("anchor", {}))
    anchor_payload = dict(anchor.get("anchor_payload", {}))
    expected_anchor_payload = _build_anchor_payload(
        final_chain_hash=str(proof.get("final_chain_hash", "")),
        event_count=int(proof.get("event_count", 0)),
        signatures=signatures,
    )
    anchor_payload_ok = anchor_payload == expected_anchor_payload
    expected_anchor_id = _anchor_id_from_payload(expected_anchor_payload)
    anchor_id_ok = str(anchor.get("anchor_id", "")) == expected_anchor_id
    return {
        "chain_integrity_ok": chain_integrity_ok,
        "final_chain_hash_ok": final_chain_hash_ok,
        "event_count_ok": event_count_ok,
        "anchor_payload_ok": anchor_payload_ok,
        "anchor_id_ok": anchor_id_ok,
    }
