# -*- coding: utf-8 -*-
"""bubble_minimal_variants.py -- the bare link, cost params stripped.

The berain link that BOOKS carries no cost_type / cost_amount / cost_currency
and no install_callback.  Every BubbleBus variant so far had them.  Adjust can
treat cost-parameter links as cost-tracking/S2S links, which is a plausible
reason the click registers but never joins.  Test the minimal shape:

  M1  campaign AH   adgroup 43407    idfa + gps_adid + click_id
  M2  campaign GWM  adgroup {43407}  idfa + gps_adid + click_id

(falls back to importing the funnel harness from bubble_ah_variants)
"""
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from bubble_ah_variants import funnel


def minimal(campaign, adgroup, idfa, cid):
    return ("https://app.adjust.com/1t8ghv6f?campaign=" + campaign
            + "&adgroup=" + adgroup
            + "&idfa=" + idfa + "&gps_adid=" + idfa
            + "&click_id=z" + cid)


if __name__ == "__main__":
    res = {}
    res["M1 AH minimal"] = funnel(
        "M1  AH  adgroup 43407   (no cost params)",
        lambda i: minimal("AH", "43407", i, uuid.uuid4().hex[:12]))
    res["M2 GWM minimal"] = funnel(
        "M2  GWM adgroup {43407} (no cost params)",
        lambda i: minimal("GWM", "%7B43407%7D", i, uuid.uuid4().hex[:12]))

    print("=" * 76)
    print("SUMMARY")
    for k, v in res.items():
        print("  %-16s %-12s / %-9s  %s / %s"
              % (k, v.get("network"), v.get("tracker_token"),
                 v.get("campaign"), v.get("adgroup")))
    paid = [k for k, v in res.items() if v.get("network") not in (None, "Organic")]
    print()
    print("BOOKED:", paid or "none")