Recorded tier-1 inputs. `{{CANARY:<tag>}}` and `{{PASSWORD:<tag>}}` are replaced at test
time (tests/test_tier1.py `fill`) with values made up for the run, so no secret-shaped
string is committed and every source plants its own canary.
